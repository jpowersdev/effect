import * as Crypto from "../../Crypto.ts"
import * as Effect from "../../Effect.ts"
import type { JoseError } from "../JoseError.ts"
import { type EncEntry, isCekTransport, jweEncryption, type JweEntry } from "./algorithms.ts"
import { checkCryptoKey, checkModulusLength, checkUsage, jwkToKey, prepareKey, rawKey } from "./key.ts"
import {
  attempt,
  b64u,
  concat,
  decodeB64u,
  encoder,
  error,
  fail,
  failSync,
  isCryptoKey,
  isObject,
  mapCryptoError,
  timingSafeEqual,
  uint32be,
  uint64be
} from "./shared.ts"

const cryptoService = Effect.service(Crypto.Crypto)

/** @internal */
export const generateCek = (enc: EncEntry) =>
  Effect.flatMap(cryptoService, (crypto) => mapCryptoError(crypto.randomBytes(enc.cekBits >> 3)))

const generateIv = (enc: EncEntry) =>
  Effect.flatMap(cryptoService, (crypto) => mapCryptoError(crypto.randomBytes(enc.ivBits >> 3)))

const checkCekLength = (cek: Uint8Array, expected: number) => {
  const actual = cek.byteLength << 3
  if (actual !== expected) {
    failSync("JweInvalid", `Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`)
  }
}

const checkIvLength = (enc: EncEntry, iv: Uint8Array) => {
  if (iv.length << 3 !== enc.ivBits) failSync("JweInvalid", "Invalid Initialization Vector length")
}

const cbcKeys = (enc: EncEntry, cek: Crypto.Key | Uint8Array, usage: "encrypt" | "decrypt") =>
  Effect.gen(function*() {
    if (!(cek instanceof Uint8Array)) {
      return yield* fail("InvalidKey", "Key for AES-CBC-HMAC content encryption must be a Uint8Array")
    }
    const keySize = enc.cekBits >> 1
    const crypto = yield* cryptoService
    const encKey = yield* mapCryptoError(
      crypto.importKey("raw", cek.subarray(keySize >> 3), { name: "AES-CBC" }, { usages: [usage] })
    )
    const macKey = yield* mapCryptoError(
      crypto.importKey("raw", cek.subarray(0, keySize >> 3), {
        name: "HMAC",
        hash: `SHA-${keySize << 1}` as Crypto.DigestAlgorithm
      }, { usages: ["sign"] })
    )
    return { encKey, macKey, keySize }
  })

const cbcTag = (macKey: Crypto.Key, macData: Uint8Array, keySize: number) =>
  Effect.flatMap(
    cryptoService,
    (crypto) =>
      Effect.map(mapCryptoError(crypto.sign({ name: "HMAC" }, macKey, macData)), (mac) => mac.slice(0, keySize >> 3))
  )

/** @internal */
export interface Encrypted {
  readonly ciphertext: Uint8Array
  readonly tag: Uint8Array
  readonly iv: Uint8Array
}

/** @internal */
export const encryptContent = (
  enc: EncEntry,
  plaintext: Uint8Array,
  cek: Crypto.Key | Uint8Array,
  providedIv: Uint8Array | undefined,
  aad: Uint8Array
): Effect.Effect<Encrypted, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
      return yield* fail("InvalidKey", "Content Encryption Key must be a Key or Uint8Array")
    }
    const iv = providedIv ?? (yield* generateIv(enc))
    yield* attempt(() => {
      checkIvLength(enc, iv)
      if (cek instanceof Uint8Array) checkCekLength(cek, enc.cekBits)
    })
    const crypto = yield* cryptoService
    if (enc.cbc) {
      const { encKey, keySize, macKey } = yield* cbcKeys(enc, cek, "encrypt")
      const ciphertext = yield* mapCryptoError(crypto.encrypt({ name: "AES-CBC", iv }, encKey, plaintext))
      const tag = yield* cbcTag(macKey, concat(aad, iv, ciphertext, uint64be(aad.length * 8)), keySize)
      return { ciphertext, tag, iv }
    }
    const key = yield* rawKey(cek, enc.key, "encrypt")
    const encrypted = yield* mapCryptoError(
      crypto.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, plaintext)
    )
    return { ciphertext: encrypted.subarray(0, -16), tag: encrypted.subarray(-16), iv }
  })

/** @internal */
export const decryptContent = (
  enc: EncEntry,
  cek: Crypto.Key | Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array | undefined,
  tag: Uint8Array | undefined,
  aad: Uint8Array
): Effect.Effect<Uint8Array, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
      return yield* fail("InvalidKey", "Content Encryption Key must be a Key or Uint8Array")
    }
    if (!iv) return yield* fail("JweInvalid", "JWE Initialization Vector missing")
    if (!tag) return yield* fail("JweInvalid", "JWE Authentication Tag missing")
    if (!enc.cbc && tag.length !== 16) return yield* fail("JweInvalid", "Invalid Authentication Tag length")
    yield* attempt(() => {
      checkIvLength(enc, iv)
      if (cek instanceof Uint8Array) checkCekLength(cek, enc.cekBits)
    })
    const crypto = yield* cryptoService
    if (enc.cbc) {
      const { encKey, keySize, macKey } = yield* cbcKeys(enc, cek, "decrypt")
      const expected = yield* cbcTag(macKey, concat(aad, iv, ciphertext, uint64be(aad.length * 8)), keySize)
      if (timingSafeEqual(tag, expected)) {
        const plaintext = yield* Effect.option(crypto.decrypt({ name: "AES-CBC", iv }, encKey, ciphertext))
        if (plaintext._tag === "Some") return plaintext.value
      }
      return yield* fail("DecryptionFailed", "decryption operation failed")
    }
    const key = yield* rawKey(cek, enc.key, "decrypt")
    return yield* Effect.mapError(
      crypto.decrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, concat(ciphertext, tag)),
      () => error("DecryptionFailed", "decryption operation failed")
    )
  })

const aeskwWrap = (alg: string, key: Crypto.Key | Uint8Array, cek: Uint8Array) =>
  Effect.gen(function*() {
    const kek = yield* rawKey(key, { name: "AES-KW", length: Number.parseInt(alg.slice(1, 4), 10) }, "wrapKey", true)
    const crypto = yield* cryptoService
    const cekKey = yield* mapCryptoError(
      crypto.importKey("raw", cek, { name: "HMAC", hash: "SHA-256" }, { extractable: true, usages: ["sign"] })
    )
    return yield* mapCryptoError(crypto.wrapKey("raw", cekKey, kek, { name: "AES-KW" }))
  })

const aeskwUnwrap = (alg: string, key: Crypto.Key | Uint8Array, encryptedKey: Uint8Array) =>
  Effect.gen(function*() {
    const kek = yield* rawKey(key, { name: "AES-KW", length: Number.parseInt(alg.slice(1, 4), 10) }, "unwrapKey", true)
    const crypto = yield* cryptoService
    const cekKey = yield* mapCryptoError(
      crypto.unwrapKey("raw", encryptedKey, kek, { name: "AES-KW" }, { name: "HMAC", hash: "SHA-256" }, {
        extractable: true,
        usages: ["sign"]
      }),
      "DecryptionFailed"
    )
    return yield* mapCryptoError(crypto.exportKey("raw", cekKey))
  })

const pbes2Derive = (p2s: Uint8Array, alg: string, p2c: number, key: Crypto.Key | Uint8Array) =>
  Effect.gen(function*() {
    if (!(p2s instanceof Uint8Array) || p2s.length < 8) {
      return yield* fail("JweInvalid", "PBES2 Salt Input must be 8 or more octets")
    }
    if (!Number.isSafeInteger(p2c) || p2c < 1) {
      return yield* fail("JweInvalid", "PBES2 Count Input must be a positive integer")
    }
    const k = yield* rawKey(key, { name: "PBKDF2" }, "deriveBits")
    const crypto = yield* cryptoService
    return yield* mapCryptoError(crypto.deriveBits(
      {
        name: "PBKDF2",
        hash: `SHA-${alg.slice(8, 11)}` as Crypto.DigestAlgorithm,
        salt: concat(encoder.encode(alg), Uint8Array.of(0), p2s),
        iterations: p2c
      },
      k,
      Number.parseInt(alg.slice(13, 16), 10)
    ))
  })

const lengthAndInput = (input: Uint8Array) => concat(uint32be(input.length), input)

const concatKdf = (z: Uint8Array, bits: number, otherInfo: Uint8Array) =>
  Effect.gen(function*() {
    const crypto = yield* cryptoService
    const length = bits >> 3
    const reps = Math.ceil(length / 32)
    const out = new Uint8Array(reps * 32)
    for (let i = 1; i <= reps; i++) {
      out.set(yield* mapCryptoError(crypto.digest("SHA-256", concat(uint32be(i), z, otherInfo))), (i - 1) * 32)
    }
    return out.slice(0, length)
  })

const checkEcdhKey = (key: Crypto.Key, usage?: Crypto.KeyUsage) => {
  if (key.algorithm.name !== "ECDH" && key.algorithm.name !== "X25519") {
    failSync("InvalidKey", "Key does not support this operation, its algorithm.name must be ECDH or X25519")
  }
  checkUsage(key, usage)
}

const ecdhesDerive = (
  publicKey: Crypto.Key,
  privateKey: Crypto.Key,
  algorithm: string,
  keyLength: number,
  apu: Uint8Array = new Uint8Array(),
  apv: Uint8Array = new Uint8Array()
) =>
  Effect.gen(function*() {
    yield* attempt(() => {
      checkEcdhKey(publicKey)
      checkEcdhKey(privateKey, "deriveBits")
    })
    const otherInfo = concat(
      lengthAndInput(encoder.encode(algorithm)),
      lengthAndInput(apu),
      lengthAndInput(apv),
      uint32be(keyLength)
    )
    const name = publicKey.algorithm.name as "ECDH" | "X25519"
    const bits = name === "X25519"
      ? 256
      : Math.ceil(Number.parseInt(publicKey.algorithm.namedCurve!.slice(-3), 10) / 8) << 3
    const crypto = yield* cryptoService
    const z = yield* mapCryptoError(crypto.deriveBits({ name, public: publicKey }, privateKey, bits))
    return yield* concatKdf(z, keyLength, otherInfo)
  })

const assertEcdhKey = (key: Crypto.Key | Uint8Array): Crypto.Key => {
  if (!isCryptoKey(key)) return failSync("InvalidKey", "Key instance expected")
  const curve = key.algorithm.namedCurve
  if (curve !== "P-256" && curve !== "P-384" && curve !== "P-521" && key.algorithm.name !== "X25519") {
    failSync("NotSupported", "ECDH with the provided key is not allowed or not supported")
  }
  return key
}

const partyInfo = (header: Record<string, unknown>, name: "apu" | "apv"): Uint8Array | undefined => {
  const value = header[name]
  if (value === undefined) return undefined
  if (typeof value !== "string") {
    return failSync("JweInvalid", `JOSE Header "${name}" (Agreement Party${name === "apu" ? "U" : "V"}Info) invalid`)
  }
  return decodeB64u(value, name, "JweInvalid")
}

const checkPartyInfo = (apu: Uint8Array | undefined, apv: Uint8Array | undefined) => {
  if (apu === undefined || apv === undefined || apu.byteLength !== apv.byteLength) return
  for (let i = 0; i < apu.byteLength; i++) if (apu[i] !== apv[i]) return
  failSync("JweInvalid", "JOSE Header \"apu\" and \"apv\" values must be distinct")
}

const checkRsaKey = (entry: JweEntry, key: Crypto.Key | Uint8Array, usage: Crypto.KeyUsage): Crypto.Key => {
  if (!isCryptoKey(key)) return failSync("InvalidKey", "Key instance expected")
  checkCryptoKey(key, entry.key!, usage)
  checkModulusLength(entry.alg, key)
  return key
}

/** @internal */
export interface KeyManagementParameters {
  readonly apu?: Uint8Array | undefined
  readonly apv?: Uint8Array | undefined
  readonly epk?: Crypto.Key | Crypto.JwkData | undefined
  readonly p2c?: number | undefined
  readonly p2s?: Uint8Array | undefined
  readonly iv?: Uint8Array | undefined
}

/** @internal */
export const encryptKeyManagement = (
  entry: JweEntry,
  enc: EncEntry,
  inputKey: unknown,
  joseHeader: Record<string, unknown>,
  providedCek: Uint8Array | undefined,
  provided: KeyManagementParameters = {}
): Effect.Effect<
  readonly [Crypto.Key | Uint8Array, Uint8Array | undefined, Record<string, unknown> | undefined],
  JoseError,
  Crypto.Crypto
> =>
  Effect.gen(function*() {
    const transport = isCekTransport(entry)
    if (providedCek !== undefined && !transport) {
      return yield* fail("InvalidArgument", `a Content Encryption Key cannot be provided with JWE "alg" ${entry.alg}`)
    }
    let key = yield* prepareKey(entry.mode === "direct-encryption" ? enc : entry, inputKey, "encrypt")
    if (entry.mode === "direct-encryption") return [key, undefined, undefined] as const
    const cek = transport ? providedCek ?? (yield* generateCek(enc)) : undefined
    if (cek) yield* attempt(() => checkCekLength(cek, enc.cekBits))
    const crypto = yield* cryptoService
    let encryptedKey: Uint8Array | undefined
    let parameters: Record<string, unknown> | undefined
    switch (entry.key?.name ?? "ECDH") {
      case "ECDH": {
        const recipient = yield* attempt(() => assertEcdhKey(key))
        const apu = provided.apu ?? (yield* attempt(() => partyInfo(joseHeader, "apu")))
        const apv = provided.apv ?? (yield* attempt(() => partyInfo(joseHeader, "apv")))
        yield* attempt(() => checkPartyInfo(apu, apv))
        let ephemeralPrivate: Crypto.Key
        let ephemeralPublic: Crypto.Key | Crypto.JwkData | undefined
        if (provided.epk !== undefined) {
          ephemeralPrivate = (yield* prepareKey(entry, provided.epk, "decrypt")) as Crypto.Key
          if (isObject(provided.epk)) {
            // A private JWK already carries its public members, so the public
            // key does not need to be exported from the imported handle.
            ephemeralPublic = provided.epk as Crypto.JwkData
          } else if (!ephemeralPrivate.extractable) {
            return yield* fail("InvalidKey", "Key for \"epk\" must be extractable")
          }
        } else {
          const algorithm: Crypto.KeyAlgorithm = recipient.algorithm.name === "X25519"
            ? { name: "X25519" }
            : { name: "ECDH", namedCurve: recipient.algorithm.namedCurve as Crypto.NamedCurve }
          const pair = (yield* mapCryptoError(
            crypto.generateKey(algorithm, { extractable: true, usages: ["deriveBits"] })
          )) as Crypto.KeyPair
          ephemeralPrivate = pair.privateKey
          ephemeralPublic = pair.publicKey
        }
        const exported = ephemeralPublic !== undefined && !isCryptoKey(ephemeralPublic)
          ? ephemeralPublic
          : yield* mapCryptoError(crypto.exportKey("jwk", ephemeralPublic ?? ephemeralPrivate))
        const direct = entry.mode === "direct-key-agreement"
        const shared = yield* ecdhesDerive(
          recipient,
          ephemeralPrivate,
          direct ? enc.alg : entry.alg,
          direct ? enc.cekBits : Number.parseInt(entry.alg.slice(-5, -2), 10),
          apu,
          apv
        )
        const epk: Record<string, unknown> = { x: exported.x, crv: exported.crv, kty: exported.kty }
        if (exported.kty === "EC") epk.y = exported.y
        parameters = { epk }
        if (provided.apu !== undefined) parameters.apu = b64u(provided.apu)
        if (provided.apv !== undefined) parameters.apv = b64u(provided.apv)
        if (direct) return [shared, undefined, parameters] as const
        key = shared
        break
      }
      case "RSA-OAEP": {
        const k = yield* attempt(() => checkRsaKey(entry, key, "encrypt"))
        encryptedKey = yield* mapCryptoError(crypto.encrypt({ name: "RSA-OAEP" }, k, cek!))
        break
      }
      case "PBKDF2": {
        const p2c = provided.p2c ?? 2048
        const p2s = provided.p2s ?? (yield* mapCryptoError(crypto.randomBytes(16)))
        key = yield* pbes2Derive(p2s, entry.alg, p2c, key)
        parameters = { p2c, p2s: b64u(p2s) }
        break
      }
      case "AES-GCM": {
        const iv = provided.iv ?? (yield* mapCryptoError(crypto.randomBytes(12)))
        const wrapped = yield* encryptContent(
          jweEncryption(entry.alg.slice(0, -2)),
          cek!,
          key,
          iv,
          new Uint8Array()
        )
        encryptedKey = wrapped.ciphertext
        parameters = { iv: b64u(wrapped.iv), tag: b64u(wrapped.tag) }
        break
      }
    }
    encryptedKey ??= yield* aeskwWrap(entry.alg.slice(-6), key, cek!)
    if (!encryptedKey.byteLength) {
      return yield* fail("InvalidArgument", "JWE key management algorithm did not produce an Encrypted Key")
    }
    return [cek!, encryptedKey, parameters] as const
  })

/** @internal */
export const decryptKeyManagement = (
  entry: JweEntry,
  enc: EncEntry,
  key: Crypto.Key | Uint8Array,
  encryptedKey: Uint8Array | undefined,
  joseHeader: Record<string, unknown>,
  maxPBES2Count: number | undefined
): Effect.Effect<Crypto.Key | Uint8Array, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (entry.mode === "direct-encryption") {
      if (encryptedKey !== undefined) return yield* fail("JweInvalid", "Encountered unexpected JWE Encrypted Key")
      return key
    }
    const direct = entry.mode === "direct-key-agreement"
    if (direct && encryptedKey !== undefined) {
      return yield* fail("JweInvalid", "Encountered unexpected JWE Encrypted Key")
    }
    if (!direct && encryptedKey === undefined) return yield* fail("JweInvalid", "JWE Encrypted Key missing")
    const crypto = yield* cryptoService
    switch (entry.key?.name ?? "ECDH") {
      case "ECDH": {
        const epk = joseHeader.epk
        if (
          !isObject(epk) ||
          ["d", "k", "p", "q", "dp", "dq", "qi", "oth", "priv"].some((p) => Object.hasOwn(epk, p))
        ) {
          return yield* fail("JweInvalid", "JOSE Header \"epk\" (Ephemeral Public Key) missing or invalid")
        }
        const recipient = yield* attempt(() => assertEcdhKey(key))
        const ephemeral = yield* jwkToKey(entry, epk as Crypto.JwkData)
        const apu = yield* attempt(() => partyInfo(joseHeader, "apu"))
        const apv = yield* attempt(() => partyInfo(joseHeader, "apv"))
        yield* attempt(() => checkPartyInfo(apu, apv))
        const shared = yield* ecdhesDerive(
          ephemeral,
          recipient,
          direct ? enc.alg : entry.alg,
          direct ? enc.cekBits : Number.parseInt(entry.alg.slice(-5, -2), 10),
          apu,
          apv
        )
        if (direct) return shared
        return yield* aeskwUnwrap(entry.alg.slice(-6), shared, encryptedKey!)
      }
      case "RSA-OAEP": {
        const k = yield* attempt(() => checkRsaKey(entry, key, "decrypt"))
        return yield* mapCryptoError(crypto.decrypt({ name: "RSA-OAEP" }, k, encryptedKey!), "DecryptionFailed")
      }
      case "PBKDF2": {
        if (typeof joseHeader.p2c !== "number") {
          return yield* fail("JweInvalid", "JOSE Header \"p2c\" (PBES2 Count) missing or invalid")
        }
        if (
          maxPBES2Count !== undefined && maxPBES2Count !== Infinity &&
          (!Number.isSafeInteger(maxPBES2Count) || maxPBES2Count < 1)
        ) {
          return yield* fail("InvalidArgument", "maxPBES2Count must be a positive safe integer or Infinity")
        }
        if (joseHeader.p2c > (maxPBES2Count ?? 10_000)) {
          return yield* fail("JweInvalid", "JOSE Header \"p2c\" (PBES2 Count) out is of acceptable bounds")
        }
        if (typeof joseHeader.p2s !== "string") {
          return yield* fail("JweInvalid", "JOSE Header \"p2s\" (PBES2 Salt) missing or invalid")
        }
        const p2s = yield* attempt(() => decodeB64u(joseHeader.p2s as string, "p2s", "JweInvalid"))
        const derived = yield* pbes2Derive(p2s, entry.alg, joseHeader.p2c, key)
        return yield* aeskwUnwrap(entry.alg.slice(-6), derived, encryptedKey!)
      }
      case "AES-GCM": {
        if (typeof joseHeader.iv !== "string") {
          return yield* fail("JweInvalid", "JOSE Header \"iv\" (Initialization Vector) missing or invalid")
        }
        if (typeof joseHeader.tag !== "string") {
          return yield* fail("JweInvalid", "JOSE Header \"tag\" (Authentication Tag) missing or invalid")
        }
        const iv = yield* attempt(() => decodeB64u(joseHeader.iv as string, "iv", "JweInvalid"))
        const tag = yield* attempt(() => decodeB64u(joseHeader.tag as string, "tag", "JweInvalid"))
        if (iv.byteLength !== 12) return yield* fail("JweInvalid", "Invalid Initialization Vector length")
        if (tag.byteLength !== 16) return yield* fail("JweInvalid", "Invalid Authentication Tag length")
        return yield* decryptContent(
          jweEncryption(entry.alg.slice(0, -2)),
          key,
          encryptedKey!,
          iv,
          tag,
          new Uint8Array()
        )
      }
      default:
        return yield* aeskwUnwrap(entry.alg.slice(-6), key, encryptedKey!)
    }
  })
