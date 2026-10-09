/**
 * Encrypts and decrypts JSON Web Encryption values (RFC 7516) in compact,
 * flattened JSON, and general JSON serializations.
 *
 * Supports RSA-OAEP, ECDH-ES (P-256, P-384, P-521, X25519), AES key wrap,
 * AES-GCM key wrap, PBES2, and direct key management, with AES-GCM and
 * AES-CBC-HMAC-SHA2 content encryption.
 *
 * **Gotchas**
 *
 * PBES2 key management is rejected unless listed in
 * `keyManagementAlgorithms`, and its iteration count is capped by
 * `maxPBES2Count`. Compression (`zip`) is not supported.
 *
 * @stability unstable
 * @since 4.0.0
 */
import * as Crypto from "../Crypto.ts"
import * as Effect from "../Effect.ts"
import * as Schema from "../Schema.ts"
import {
  type EncEntry,
  isCekTransport,
  JWE,
  jweAlgorithm,
  jweEncryption,
  type JweEntry
} from "./internal/algorithms.ts"
import {
  ascii,
  attemptWith,
  b64u,
  concat,
  decodeB64u,
  encoder,
  isCryptoKey,
  isDisjoint,
  isObject,
  JWE_RECOGNIZED,
  mapPlatformError,
  parseHeader,
  raise,
  serializeHeader,
  timingSafeEqual,
  uint32be,
  uint64be,
  validateAlgorithms,
  validateCrit
} from "./internal/shared.ts"
import type * as JsonWebAlgorithm from "./JsonWebAlgorithm.ts"
import { AlgorithmNotAllowedError } from "./JsonWebAlgorithm.ts"
import {
  checkCryptoKey,
  checkModulusLength,
  checkUsage,
  InvalidKeyError,
  jwkToKey,
  type KeyError,
  prepareKey,
  rawKey,
  unsupportedByRuntime,
  UnsupportedKeyError
} from "./JsonWebKey.ts"

/**
 * Error raised when a JWE is structurally invalid: the wrong number of
 * segments, segments that are not base64url, a protected header that is not a
 * JSON object, missing `alg` or `enc`, invalid key management header
 * parameters, or an initialization vector, tag, or key of the wrong length.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class MalformedJweError
  extends Schema.TaggedError<MalformedJweError>("effect/jose/JsonWebEncryption/MalformedJweError")(
    "MalformedJweError",
    { message: Schema.String }
  )
{}

/**
 * Error raised when authenticated decryption fails.
 *
 * **Details**
 *
 * The same error is raised whether the content encryption key could not be
 * recovered or the ciphertext failed authentication, so that failures do not
 * reveal which step failed (RFC 7516 section 11.5).
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class DecryptionError
  extends Schema.TaggedError<DecryptionError>("effect/jose/JsonWebEncryption/DecryptionError")(
    "DecryptionError",
    { message: Schema.String }
  )
{}

/**
 * Error raised when a JWE uses a header feature that is not supported: a
 * critical (`crit`) extension the caller has not declared as understood, or
 * compression (`zip`).
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class UnsupportedJweHeaderError
  extends Schema.TaggedError<UnsupportedJweHeaderError>("effect/jose/JsonWebEncryption/UnsupportedJweHeaderError")(
    "UnsupportedJweHeaderError",
    { message: Schema.String }
  )
{}

/**
 * Failures from producing a JWE.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type EncryptError = MalformedJweError | UnsupportedJweHeaderError | KeyError

/**
 * Failures from decrypting a JWE.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type DecryptError = EncryptError | AlgorithmNotAllowedError | DecryptionError

const malformed = (message: string) => new MalformedJweError({ message })
const unsupportedHeader = (message: string) => new UnsupportedJweHeaderError({ message })
const decryptionFailed = () => new DecryptionError({ message: "decryption operation failed" })
const invalidKey = (message: string) => new InvalidKeyError({ message })
const attemptEncrypt = attemptWith<EncryptError>()
const attempt = attemptWith<DecryptError>()

/**
 * Header parameters of a JWE.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface Header {
  readonly alg?: JsonWebAlgorithm.KeyManagementAlgorithm | (string & {}) | undefined
  readonly enc?: JsonWebAlgorithm.ContentEncryptionAlgorithm | (string & {}) | undefined
  readonly kid?: string | undefined
  readonly typ?: string | undefined
  readonly cty?: string | undefined
  readonly crit?: ReadonlyArray<string> | undefined
  readonly [parameter: string]: unknown
}

/**
 * A JWE in flattened JSON serialization.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface Flattened {
  readonly protected?: string | undefined
  readonly unprotected?: Header | undefined
  readonly header?: Header | undefined
  readonly encrypted_key?: string | undefined
  readonly iv?: string | undefined
  readonly ciphertext: string
  readonly tag?: string | undefined
  readonly aad?: string | undefined
}

/**
 * A JWE in general JSON serialization.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface General {
  readonly protected?: string | undefined
  readonly unprotected?: Header | undefined
  readonly recipients: ReadonlyArray<
    { readonly header?: Header | undefined; readonly encrypted_key?: string | undefined }
  >
  readonly iv?: string | undefined
  readonly ciphertext: string
  readonly tag?: string | undefined
  readonly aad?: string | undefined
}

/**
 * A key accepted by JWE operations: a `Crypto.Key`, raw secret bytes for
 * symmetric algorithms, or a JSON Web Key.
 *
 * **Gotchas**
 *
 * A JSON Web Key is imported on every call. To avoid repeated imports,
 * import it once with `JsonWebKey.importJwk` and pass the resulting key, or
 * provide `JsonWebKey.layerKeyCache`.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Key = Crypto.Key | Uint8Array | Crypto.JwkData

/**
 * Selects a decryption key from a JWE's headers.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type KeyResolver<E = never, R = never> = (
  protectedHeader: Header | undefined,
  token: Flattened
) => Effect.Effect<Key, E, R>

/**
 * Parameters for key management algorithms.
 *
 * **Details**
 *
 * - `apu`, `apv`: ECDH-ES agreement party information.
 * - `epk`: ECDH-ES ephemeral private key (generated when omitted).
 * - `p2c`, `p2s`: PBES2 iteration count (2048 by default) and salt.
 * - `iv`: AES-GCM key wrap initialization vector.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface KeyManagementParameters {
  readonly apu?: Uint8Array | undefined
  readonly apv?: Uint8Array | undefined
  readonly epk?: Crypto.Key | Crypto.JwkData | undefined
  readonly p2c?: number | undefined
  readonly p2s?: Uint8Array | undefined
  readonly iv?: Uint8Array | undefined
}

/**
 * Options for producing a JWE.
 *
 * **Details**
 *
 * `cek` and `iv` override the generated content encryption key and
 * initialization vector, which is only appropriate for testing.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface EncryptOptions {
  readonly key: Key
  readonly protectedHeader?: Header | undefined
  readonly sharedUnprotectedHeader?: Header | undefined
  readonly unprotectedHeader?: Header | undefined
  readonly additionalAuthenticatedData?: Uint8Array | undefined
  readonly cek?: Uint8Array | undefined
  readonly iv?: Uint8Array | undefined
  readonly keyManagementParameters?: KeyManagementParameters | undefined
  readonly crit?: Readonly<Record<string, boolean>> | undefined
}

/**
 * Options for JWE decryption.
 *
 * **Details**
 *
 * `keyManagementAlgorithms` and `contentEncryptionAlgorithms` restrict the
 * accepted `alg` and `enc` values. PBES2 algorithms must be allowed
 * explicitly. `maxPBES2Count` caps the PBES2 iteration count (10000 by
 * default).
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface DecryptOptions {
  readonly keyManagementAlgorithms?: ReadonlyArray<string> | undefined
  readonly contentEncryptionAlgorithms?: ReadonlyArray<string> | undefined
  readonly crit?: Readonly<Record<string, boolean>> | undefined
  readonly maxPBES2Count?: number | undefined
}

/**
 * The result of a successful decryption.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface DecryptResult {
  readonly plaintext: Uint8Array
  readonly protectedHeader?: Header | undefined
  readonly sharedUnprotectedHeader?: Header | undefined
  readonly unprotectedHeader?: Header | undefined
  readonly additionalAuthenticatedData?: Uint8Array | undefined
}

const cryptoService = Effect.service(Crypto.Crypto)

const generateCek = (enc: EncEntry) => Effect.flatMap(cryptoService, (crypto) => (crypto.randomBytes(enc.cekBits >> 3)))

const generateIv = (enc: EncEntry) => Effect.flatMap(cryptoService, (crypto) => (crypto.randomBytes(enc.ivBits >> 3)))

const checkCekLength = (cek: Uint8Array, expected: number) => {
  const actual = cek.byteLength << 3
  if (actual !== expected) {
    raise(malformed(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`))
  }
}

const checkIvLength = (enc: EncEntry, iv: Uint8Array) => {
  if (iv.length << 3 !== enc.ivBits) raise(malformed("Invalid Initialization Vector length"))
}

const cbcKeys = (enc: EncEntry, cek: Crypto.Key | Uint8Array, usage: "encrypt" | "decrypt") =>
  Effect.gen(function*() {
    if (!(cek instanceof Uint8Array)) {
      return yield* Effect.fail(invalidKey("Key for AES-CBC-HMAC content encryption must be a Uint8Array"))
    }
    const keySize = enc.cekBits >> 1
    const crypto = yield* cryptoService
    const encKey = yield* mapPlatformError(
      crypto.importKey("raw", cek.subarray(keySize >> 3), { name: "AES-CBC" }, { usages: [usage] }),
      (error) => unsupportedByRuntime({ name: "AES-CBC" }, error, keySize) ?? error
    )
    const macKey = yield* (crypto.importKey("raw", cek.subarray(0, keySize >> 3), {
      name: "HMAC",
      hash: `SHA-${keySize << 1}` as Crypto.DigestAlgorithm
    }, { usages: ["sign"] }))
    return { encKey, macKey, keySize }
  })

const cbcTag = (macKey: Crypto.Key, macData: Uint8Array, keySize: number) =>
  Effect.flatMap(
    cryptoService,
    (crypto) => Effect.map(crypto.sign({ name: "HMAC" }, macKey, macData), (mac) => mac.slice(0, keySize >> 3))
  )

interface Encrypted {
  readonly ciphertext: Uint8Array
  readonly tag: Uint8Array
  readonly iv: Uint8Array
}

const encryptContent = (
  enc: EncEntry,
  plaintext: Uint8Array,
  cek: Crypto.Key | Uint8Array,
  providedIv: Uint8Array | undefined,
  aad: Uint8Array
): Effect.Effect<Encrypted, EncryptError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
      return yield* Effect.fail(invalidKey("Content Encryption Key must be a Key or Uint8Array"))
    }
    const iv = providedIv ?? (yield* generateIv(enc))
    yield* attemptEncrypt(() => {
      checkIvLength(enc, iv)
      if (cek instanceof Uint8Array) checkCekLength(cek, enc.cekBits)
    })
    const crypto = yield* cryptoService
    if (enc.cbc) {
      const { encKey, keySize, macKey } = yield* cbcKeys(enc, cek, "encrypt")
      const ciphertext = yield* (crypto.encrypt({ name: "AES-CBC", iv }, encKey, plaintext))
      const tag = yield* cbcTag(macKey, concat(aad, iv, ciphertext, uint64be(aad.length * 8)), keySize)
      return { ciphertext, tag, iv }
    }
    const key = yield* rawKey(cek, enc.key, "encrypt")
    const encrypted =
      yield* (crypto.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, plaintext))
    return { ciphertext: encrypted.subarray(0, -16), tag: encrypted.subarray(-16), iv }
  })

const decryptContent = (
  enc: EncEntry,
  cek: Crypto.Key | Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array | undefined,
  tag: Uint8Array | undefined,
  aad: Uint8Array
): Effect.Effect<Uint8Array, DecryptError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
      return yield* Effect.fail(invalidKey("Content Encryption Key must be a Key or Uint8Array"))
    }
    if (!iv) return yield* Effect.fail(malformed("JWE Initialization Vector missing"))
    if (!tag) return yield* Effect.fail(malformed("JWE Authentication Tag missing"))
    if (!enc.cbc && tag.length !== 16) return yield* Effect.fail(malformed("Invalid Authentication Tag length"))
    yield* attemptEncrypt(() => {
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
      return yield* Effect.fail(decryptionFailed())
    }
    const key = yield* rawKey(cek, enc.key, "decrypt")
    return yield* Effect.mapError(
      crypto.decrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, concat(ciphertext, tag)),
      () => decryptionFailed()
    )
  })

const aeskwWrap = (alg: string, key: Crypto.Key | Uint8Array, cek: Uint8Array) =>
  Effect.gen(function*() {
    const kek = yield* rawKey(key, { name: "AES-KW", length: Number.parseInt(alg.slice(1, 4), 10) }, "wrapKey", true)
    const crypto = yield* cryptoService
    const cekKey =
      yield* (crypto.importKey("raw", cek, { name: "HMAC", hash: "SHA-256" }, { extractable: true, usages: ["sign"] }))
    return yield* (crypto.wrapKey("raw", cekKey, kek, { name: "AES-KW" }))
  })

const aeskwUnwrap = (alg: string, key: Crypto.Key | Uint8Array, encryptedKey: Uint8Array) =>
  Effect.gen(function*() {
    const kek = yield* rawKey(key, { name: "AES-KW", length: Number.parseInt(alg.slice(1, 4), 10) }, "unwrapKey", true)
    const crypto = yield* cryptoService
    const cekKey = yield* mapPlatformError(
      crypto.unwrapKey("raw", encryptedKey, kek, { name: "AES-KW" }, { name: "HMAC", hash: "SHA-256" }, {
        extractable: true,
        usages: ["sign"]
      }),
      decryptionFailed
    )
    return yield* (crypto.exportKey("raw", cekKey))
  })

const pbes2Derive = (p2s: Uint8Array, alg: string, p2c: number, key: Crypto.Key | Uint8Array) =>
  Effect.gen(function*() {
    if (!(p2s instanceof Uint8Array) || p2s.length < 8) {
      return yield* Effect.fail(malformed("PBES2 Salt Input must be 8 or more octets"))
    }
    if (!Number.isSafeInteger(p2c) || p2c < 1) {
      return yield* Effect.fail(malformed("PBES2 Count Input must be a positive integer"))
    }
    const k = yield* rawKey(key, { name: "PBKDF2" }, "deriveBits")
    const crypto = yield* cryptoService
    return yield* (crypto.deriveBits(
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
      out.set(yield* (crypto.digest("SHA-256", concat(uint32be(i), z, otherInfo))), (i - 1) * 32)
    }
    return out.slice(0, length)
  })

const checkEcdhKey = (key: Crypto.Key, usage?: Crypto.KeyUsage) => {
  if (key.algorithm.name !== "ECDH" && key.algorithm.name !== "X25519") {
    raise(invalidKey("Key does not support this operation, its algorithm.name must be ECDH or X25519"))
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
    yield* attemptEncrypt(() => {
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
    const z = yield* (crypto.deriveBits({ name, public: publicKey }, privateKey, bits))
    return yield* concatKdf(z, keyLength, otherInfo)
  })

const assertEcdhKey = (key: Crypto.Key | Uint8Array): Crypto.Key => {
  if (!isCryptoKey(key)) return raise(invalidKey("Key instance expected"))
  const curve = key.algorithm.namedCurve
  if (curve !== "P-256" && curve !== "P-384" && curve !== "P-521" && key.algorithm.name !== "X25519") {
    raise(new UnsupportedKeyError({ message: "ECDH with the provided key is not allowed or not supported" }))
  }
  return key
}

const partyInfo = (header: Record<string, unknown>, name: "apu" | "apv"): Uint8Array | undefined => {
  const value = header[name]
  if (value === undefined) return undefined
  if (typeof value !== "string") {
    return raise(malformed(`JOSE Header "${name}" (Agreement Party${name === "apu" ? "U" : "V"}Info) invalid`))
  }
  return decodeB64u(value, name, malformed)
}

const checkPartyInfo = (apu: Uint8Array | undefined, apv: Uint8Array | undefined) => {
  if (apu === undefined || apv === undefined || apu.byteLength !== apv.byteLength) return
  for (let i = 0; i < apu.byteLength; i++) if (apu[i] !== apv[i]) return
  raise(malformed("JOSE Header \"apu\" and \"apv\" values must be distinct"))
}

const checkRsaKey = (entry: JweEntry, key: Crypto.Key | Uint8Array, usage: Crypto.KeyUsage): Crypto.Key => {
  if (!isCryptoKey(key)) return raise(invalidKey("Key instance expected"))
  checkCryptoKey(key, entry.key!, usage)
  checkModulusLength(entry.alg, key)
  return key
}

const encryptKeyManagement = (
  entry: JweEntry,
  enc: EncEntry,
  inputKey: unknown,
  joseHeader: Record<string, unknown>,
  providedCek: Uint8Array | undefined,
  provided: KeyManagementParameters = {}
): Effect.Effect<
  readonly [Crypto.Key | Uint8Array, Uint8Array | undefined, Record<string, unknown> | undefined],
  EncryptError,
  Crypto.Crypto
> =>
  Effect.gen(function*() {
    const transport = isCekTransport(entry)
    if (providedCek !== undefined && !transport) {
      return yield* Effect.die(new TypeError(`a Content Encryption Key cannot be provided with JWE "alg" ${entry.alg}`))
    }
    let key = yield* prepareKey(entry.mode === "direct-encryption" ? enc : entry, inputKey, "encrypt")
    if (entry.mode === "direct-encryption") return [key, undefined, undefined] as const
    const cek = transport ? providedCek ?? (yield* generateCek(enc)) : undefined
    if (cek) yield* attemptEncrypt(() => checkCekLength(cek, enc.cekBits))
    const crypto = yield* cryptoService
    let encryptedKey: Uint8Array | undefined
    let parameters: Record<string, unknown> | undefined
    switch (entry.key?.name ?? "ECDH") {
      case "ECDH": {
        const recipient = yield* attemptEncrypt(() => assertEcdhKey(key))
        const apu = provided.apu ?? (yield* attemptEncrypt(() => partyInfo(joseHeader, "apu")))
        const apv = provided.apv ?? (yield* attemptEncrypt(() => partyInfo(joseHeader, "apv")))
        yield* attemptEncrypt(() => checkPartyInfo(apu, apv))
        let ephemeralPrivate: Crypto.Key
        let ephemeralPublic: Crypto.Key | Crypto.JwkData | undefined
        if (provided.epk !== undefined) {
          ephemeralPrivate = (yield* prepareKey(entry, provided.epk, "decrypt")) as Crypto.Key
          if (isObject(provided.epk)) {
            // A private JWK already carries its public members, so the public
            // key does not need to be exported from the imported handle.
            ephemeralPublic = provided.epk as Crypto.JwkData
          } else if (!ephemeralPrivate.extractable) {
            return yield* Effect.fail(invalidKey("Key for \"epk\" must be extractable"))
          }
        } else {
          const algorithm: Crypto.KeyAlgorithm = recipient.algorithm.name === "X25519"
            ? { name: "X25519" }
            : { name: "ECDH", namedCurve: recipient.algorithm.namedCurve as Crypto.NamedCurve }
          const pair =
            (yield* (crypto.generateKey(algorithm, { extractable: true, usages: ["deriveBits"] }))) as Crypto.KeyPair
          ephemeralPrivate = pair.privateKey
          ephemeralPublic = pair.publicKey
        }
        const exported = ephemeralPublic !== undefined && !isCryptoKey(ephemeralPublic)
          ? ephemeralPublic
          : yield* (crypto.exportKey("jwk", ephemeralPublic ?? ephemeralPrivate))
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
        const k = yield* attemptEncrypt(() => checkRsaKey(entry, key, "encrypt"))
        encryptedKey = yield* (crypto.encrypt({ name: "RSA-OAEP" }, k, cek!))
        break
      }
      case "PBKDF2": {
        const p2c = provided.p2c ?? 2048
        const p2s = provided.p2s ?? (yield* (crypto.randomBytes(16)))
        key = yield* pbes2Derive(p2s, entry.alg, p2c, key)
        parameters = { p2c, p2s: b64u(p2s) }
        break
      }
      case "AES-GCM": {
        const iv = provided.iv ?? (yield* (crypto.randomBytes(12)))
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
      return yield* Effect.die(new TypeError("JWE key management algorithm did not produce an Encrypted Key"))
    }
    return [cek!, encryptedKey, parameters] as const
  })

const decryptKeyManagement = (
  entry: JweEntry,
  enc: EncEntry,
  key: Crypto.Key | Uint8Array,
  encryptedKey: Uint8Array | undefined,
  joseHeader: Record<string, unknown>,
  maxPBES2Count: number | undefined
): Effect.Effect<Crypto.Key | Uint8Array, DecryptError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (entry.mode === "direct-encryption") {
      if (encryptedKey !== undefined) return yield* Effect.fail(malformed("Encountered unexpected JWE Encrypted Key"))
      return key
    }
    const direct = entry.mode === "direct-key-agreement"
    if (direct && encryptedKey !== undefined) {
      return yield* Effect.fail(malformed("Encountered unexpected JWE Encrypted Key"))
    }
    if (!direct && encryptedKey === undefined) return yield* Effect.fail(malformed("JWE Encrypted Key missing"))
    const crypto = yield* cryptoService
    switch (entry.key?.name ?? "ECDH") {
      case "ECDH": {
        const epk = joseHeader.epk
        if (
          !isObject(epk) ||
          ["d", "k", "p", "q", "dp", "dq", "qi", "oth", "priv"].some((p) => Object.hasOwn(epk, p))
        ) {
          return yield* Effect.fail(malformed("JOSE Header \"epk\" (Ephemeral Public Key) missing or invalid"))
        }
        const recipient = yield* attemptEncrypt(() => assertEcdhKey(key))
        const ephemeral = yield* jwkToKey(entry, epk as Crypto.JwkData)
        const apu = yield* attemptEncrypt(() => partyInfo(joseHeader, "apu"))
        const apv = yield* attemptEncrypt(() => partyInfo(joseHeader, "apv"))
        yield* attemptEncrypt(() => checkPartyInfo(apu, apv))
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
        const k = yield* attemptEncrypt(() => checkRsaKey(entry, key, "decrypt"))
        return yield* mapPlatformError(crypto.decrypt({ name: "RSA-OAEP" }, k, encryptedKey!), decryptionFailed)
      }
      case "PBKDF2": {
        if (typeof joseHeader.p2c !== "number") {
          return yield* Effect.fail(malformed("JOSE Header \"p2c\" (PBES2 Count) missing or invalid"))
        }
        if (
          maxPBES2Count !== undefined && maxPBES2Count !== Infinity &&
          (!Number.isSafeInteger(maxPBES2Count) || maxPBES2Count < 1)
        ) {
          return yield* Effect.die(new TypeError("maxPBES2Count must be a positive safe integer or Infinity"))
        }
        if (joseHeader.p2c > (maxPBES2Count ?? 10_000)) {
          return yield* Effect.fail(malformed("JOSE Header \"p2c\" (PBES2 Count) out is of acceptable bounds"))
        }
        if (typeof joseHeader.p2s !== "string") {
          return yield* Effect.fail(malformed("JOSE Header \"p2s\" (PBES2 Salt) missing or invalid"))
        }
        const p2s = yield* attemptEncrypt(() => decodeB64u(joseHeader.p2s as string, "p2s", malformed))
        const derived = yield* pbes2Derive(p2s, entry.alg, joseHeader.p2c, key)
        return yield* aeskwUnwrap(entry.alg.slice(-6), derived, encryptedKey!)
      }
      case "AES-GCM": {
        if (typeof joseHeader.iv !== "string") {
          return yield* Effect.fail(malformed("JOSE Header \"iv\" (Initialization Vector) missing or invalid"))
        }
        if (typeof joseHeader.tag !== "string") {
          return yield* Effect.fail(malformed("JOSE Header \"tag\" (Authentication Tag) missing or invalid"))
        }
        const iv = yield* attemptEncrypt(() => decodeB64u(joseHeader.iv as string, "iv", malformed))
        const tag = yield* attemptEncrypt(() => decodeB64u(joseHeader.tag as string, "tag", malformed))
        if (iv.byteLength !== 12) return yield* Effect.fail(malformed("Invalid Initialization Vector length"))
        if (tag.byteLength !== 16) return yield* Effect.fail(malformed("Invalid Authentication Tag length"))
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

const toBytes = (input: Uint8Array | string): Uint8Array =>
  typeof input === "string" ? new TextEncoder().encode(input) : input

const checkDisjoint = (...headers: ReadonlyArray<object | undefined>) => {
  if (!isDisjoint(...headers)) {
    raise(
      malformed("JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint")
    )
  }
}

const rejectZip = (joseHeader: Record<string, unknown>) => {
  if (joseHeader.zip !== undefined) {
    raise(unsupportedHeader("JWE \"zip\" (Compression Algorithm) Header Parameter is not supported"))
  }
}

interface Checked {
  readonly protectedHeader: Record<string, unknown> | undefined
  readonly unprotectedHeader: Record<string, unknown> | undefined
  readonly sharedUnprotectedHeader: Record<string, unknown> | undefined
  readonly joseHeader: Record<string, unknown>
  readonly enc: ReturnType<typeof jweEncryption>
  readonly entry: JweEntry
}

const checkEncryptHeaders = (options: Omit<EncryptOptions, "key">): Checked => {
  if (!options.protectedHeader && !options.unprotectedHeader && !options.sharedUnprotectedHeader) {
    raise(malformed("either a protected, shared unprotected, or unprotected header must be provided"))
  }
  const protectedHeader = options.protectedHeader && serializeHeader(malformed, options.protectedHeader)[0]
  const unprotectedHeader = options.unprotectedHeader && serializeHeader(malformed, options.unprotectedHeader)[0]
  const sharedUnprotectedHeader = options.sharedUnprotectedHeader &&
    serializeHeader(malformed, options.sharedUnprotectedHeader)[0]
  checkDisjoint(protectedHeader, unprotectedHeader, sharedUnprotectedHeader)
  const joseHeader = { ...protectedHeader, ...unprotectedHeader, ...sharedUnprotectedHeader }
  validateCrit(malformed, unsupportedHeader, JWE_RECOGNIZED, options.crit, protectedHeader, joseHeader)
  rejectZip(joseHeader)
  const { alg, enc } = joseHeader
  if (typeof alg !== "string" || !alg) {
    raise(malformed("JWE \"alg\" (Algorithm) Header Parameter missing or invalid"))
  }
  if (typeof enc !== "string" || !enc) {
    raise(malformed("JWE \"enc\" (Encryption Algorithm) Header Parameter missing or invalid"))
  }
  return {
    protectedHeader,
    unprotectedHeader,
    sharedUnprotectedHeader,
    joseHeader,
    enc: jweEncryption(enc),
    entry: jweAlgorithm(alg)
  }
}

const encryptJwe = (
  plaintext: Uint8Array,
  checked: Checked,
  options: EncryptOptions,
  unprotectedParameters = false
): Effect.Effect<Flattened, EncryptError, Crypto.Crypto> =>
  Effect.gen(function*() {
    let { protectedHeader, unprotectedHeader } = checked
    const [cek, encryptedKey, parameters] = yield* encryptKeyManagement(
      checked.entry,
      checked.enc,
      options.key,
      checked.joseHeader,
      options.cek,
      options.keyManagementParameters
    )
    if (parameters) {
      // With several recipients, per-recipient key management parameters
      // belong in that recipient's unprotected header.
      if (unprotectedParameters) {
        unprotectedHeader = unprotectedHeader
          ? { ...unprotectedHeader, ...parameters }
          : parameters
      } else protectedHeader = protectedHeader ? { ...protectedHeader, ...parameters } : parameters
      yield* attemptEncrypt(() => checkDisjoint(protectedHeader, unprotectedHeader, checked.sharedUnprotectedHeader))
    }
    const protectedString = protectedHeader ? b64u(JSON.stringify(protectedHeader)) : ""
    const aad = options.additionalAuthenticatedData
    const aadMember = aad?.byteLength ? b64u(aad) : undefined
    const additionalData = ascii(aadMember ? `${protectedString}.${aadMember}` : protectedString)!
    const { ciphertext, iv, tag } = yield* encryptContent(
      checked.enc,
      plaintext,
      cek,
      options.iv,
      additionalData
    )
    const jwe: {
      -readonly [K in keyof Flattened]: Flattened[K]
    } = { ciphertext: b64u(ciphertext), iv: b64u(iv), tag: b64u(tag) }
    if (encryptedKey?.byteLength) jwe.encrypted_key = b64u(encryptedKey)
    if (aadMember) jwe.aad = aadMember
    if (protectedHeader) jwe.protected = protectedString
    if (checked.sharedUnprotectedHeader) jwe.unprotected = checked.sharedUnprotectedHeader
    if (unprotectedHeader) jwe.header = unprotectedHeader
    return jwe
  })

/**
 * Produces a JWE in flattened JSON serialization.
 *
 * @stability unstable
 * @category encryption
 * @since 4.0.0
 */
export const encryptFlattened = (
  plaintext: Uint8Array | string,
  options: EncryptOptions
): Effect.Effect<Flattened, EncryptError, Crypto.Crypto> =>
  Effect.flatMap(
    attemptEncrypt(() => checkEncryptHeaders(options)),
    (checked) => encryptJwe(toBytes(plaintext), checked, options)
  )

/**
 * Produces a JWE in compact serialization.
 *
 * **Example** (Encrypting and decrypting with a shared key)
 *
 * ```ts
 * import { Effect } from "effect"
 * import { JsonWebEncryption, JsonWebKey } from "effect/jose"
 *
 * const program = Effect.gen(function*() {
 *   const key = yield* JsonWebKey.generateSecret("A256KW")
 *   const jwe = yield* JsonWebEncryption.encryptCompact("secret message", {
 *     key,
 *     protectedHeader: { alg: "A256KW", enc: "A256GCM" }
 *   })
 *   const { plaintext } = yield* JsonWebEncryption.decryptCompact(jwe, key)
 *   return new TextDecoder().decode(plaintext)
 * })
 * ```
 *
 * @stability unstable
 * @category encryption
 * @since 4.0.0
 */
export const encryptCompact = (
  plaintext: Uint8Array | string,
  options: Omit<EncryptOptions, "unprotectedHeader" | "sharedUnprotectedHeader" | "additionalAuthenticatedData"> & {
    readonly protectedHeader: Header
  }
): Effect.Effect<string, EncryptError, Crypto.Crypto> =>
  Effect.map(
    encryptFlattened(plaintext, options),
    (jwe) => [jwe.protected, jwe.encrypted_key ?? "", jwe.iv ?? "", jwe.ciphertext, jwe.tag ?? ""].join(".")
  )

/**
 * A recipient of a general JWE.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface Recipient {
  readonly key: Key
  readonly unprotectedHeader?: Header | undefined
  readonly keyManagementParameters?: KeyManagementParameters | undefined
  readonly crit?: Readonly<Record<string, boolean>> | undefined
}

/**
 * Produces a JWE in general JSON serialization for one or more recipients.
 *
 * **Gotchas**
 *
 * All recipients must use the same `enc`, and direct key agreement or direct
 * encryption algorithms allow only a single recipient.
 *
 * @stability unstable
 * @category encryption
 * @since 4.0.0
 */
export const encryptGeneral = (
  plaintext: Uint8Array | string,
  options: {
    readonly recipients: ReadonlyArray<Recipient>
    readonly protectedHeader?: Header | undefined
    readonly sharedUnprotectedHeader?: Header | undefined
    readonly additionalAuthenticatedData?: Uint8Array | undefined
  }
): Effect.Effect<General, EncryptError, Crypto.Crypto> =>
  Effect.gen(function*() {
    const { recipients } = options
    if (recipients.length === 0) return yield* Effect.fail(malformed("at least one recipient must be added"))
    const multiple = recipients.length > 1
    const checkedRecipients = yield* attemptEncrypt(() => {
      let enc: string | undefined
      return recipients.map((recipient) => {
        const checked = checkEncryptHeaders({
          protectedHeader: options.protectedHeader,
          sharedUnprotectedHeader: options.sharedUnprotectedHeader,
          unprotectedHeader: recipient.unprotectedHeader,
          crit: recipient.crit
        })
        if (multiple && !isCekTransport(checked.entry)) {
          raise(malformed(`"${checked.entry.alg}" alg may only have a single recipient`))
        }
        if (enc === undefined) enc = checked.enc.alg
        else if (enc !== checked.enc.alg) {
          raise(malformed("JWE \"enc\" (Encryption Algorithm) Header Parameter must be the same for all recipients"))
        }
        return checked
      })
    })
    const first = checkedRecipients[0]
    const cek = multiple ? yield* generateCek(first.enc) : undefined
    const plaintextBytes = toBytes(plaintext)
    const { encrypted_key, header, ...shared } = yield* encryptJwe(plaintextBytes, first, {
      key: recipients[0].key,
      protectedHeader: options.protectedHeader,
      sharedUnprotectedHeader: options.sharedUnprotectedHeader,
      unprotectedHeader: recipients[0].unprotectedHeader,
      additionalAuthenticatedData: options.additionalAuthenticatedData,
      cek,
      keyManagementParameters: recipients[0].keyManagementParameters,
      crit: recipients[0].crit
    }, multiple)
    const out: Array<{ header?: Header; encrypted_key?: string }> = [{}]
    if (encrypted_key) out[0].encrypted_key = encrypted_key
    if (header) out[0].header = header
    for (let i = 1; i < recipients.length; i++) {
      const checked = checkedRecipients[i]
      const [, encryptedKey, parameters] = yield* encryptKeyManagement(
        checked.entry,
        checked.enc,
        recipients[i].key,
        checked.joseHeader,
        cek,
        recipients[i].keyManagementParameters
      )
      const target: { header?: Header; encrypted_key?: string } = { encrypted_key: b64u(encryptedKey!) }
      if (checked.unprotectedHeader || parameters) {
        const merged = { ...checked.unprotectedHeader, ...parameters }
        if (parameters) {
          yield* attemptEncrypt(() => checkDisjoint(checked.protectedHeader, merged, checked.sharedUnprotectedHeader))
        }
        target.header = merged
      }
      out.push(target)
    }
    return { ...shared, recipients: out } as General
  })

const snapshotShared = (jwe: Record<string, unknown>) => {
  const { aad, ciphertext, iv, protected: encodedProtected, tag, unprotected } = jwe
  if (iv !== undefined && (typeof iv !== "string" || !iv)) {
    raise(malformed("JWE Initialization Vector incorrect type"))
  }
  if (typeof ciphertext !== "string") raise(malformed("JWE Ciphertext missing or incorrect type"))
  if (tag !== undefined && (typeof tag !== "string" || !tag)) {
    raise(malformed("JWE Authentication Tag incorrect type"))
  }
  if (encodedProtected !== undefined && typeof encodedProtected !== "string") {
    raise(malformed("JWE Protected Header incorrect type"))
  }
  if (aad !== undefined && (typeof aad !== "string" || !aad)) raise(malformed("JWE AAD incorrect type"))
  if (unprotected !== undefined && !isObject(unprotected)) {
    raise(malformed("JWE Shared Unprotected Header incorrect type"))
  }
}

const checkRecipient = (jwe: Record<string, unknown>) => {
  const { encrypted_key: encryptedKey, header } = jwe
  if (encryptedKey !== undefined && typeof encryptedKey !== "string") {
    raise(malformed("JWE Encrypted Key incorrect type"))
  }
  if (header !== undefined && !isObject(header)) {
    raise(malformed("JWE Per-Recipient Unprotected Header incorrect type"))
  }
  if (jwe.protected === undefined && header === undefined && jwe.unprotected === undefined) {
    raise(malformed("JOSE Header missing"))
  }
}

const decryptJwe = <E, R>(
  jwe: Flattened,
  options: DecryptOptions | undefined,
  key: Key | KeyResolver<E, R>
): Effect.Effect<DecryptResult, DecryptError | E, Crypto.Crypto | R> =>
  Effect.gen(function*() {
    const checked = yield* attempt(() => {
      const parsedProtected = jwe.protected === undefined
        ? undefined
        : parseHeader(jwe.protected, malformed, "JWE Protected Header is invalid")
      const ciphertext = decodeB64u(jwe.ciphertext, "ciphertext", malformed)
      const iv = jwe.iv !== undefined ? decodeB64u(jwe.iv, "iv", malformed) : undefined
      const tag = jwe.tag !== undefined ? decodeB64u(jwe.tag, "tag", malformed) : undefined
      const additionalData = ascii((jwe.protected ?? "") + (jwe.aad !== undefined ? `.${jwe.aad}` : "")) ??
        raise(malformed("The aad is not a valid base64url string"))
      let joseHeader: Record<string, unknown>
      if (jwe.header !== undefined || jwe.unprotected !== undefined) {
        if (!isDisjoint(parsedProtected, jwe.header, jwe.unprotected)) {
          raise(
            malformed(
              "JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint"
            )
          )
        }
        joseHeader = { ...parsedProtected, ...jwe.header, ...jwe.unprotected }
      } else {
        joseHeader = parsedProtected ?? {}
      }
      const keyManagementAlgorithms = validateAlgorithms("keyManagementAlgorithms", options?.keyManagementAlgorithms)
      const contentEncryptionAlgorithms = validateAlgorithms(
        "contentEncryptionAlgorithms",
        options?.contentEncryptionAlgorithms
      )
      validateCrit(malformed, unsupportedHeader, JWE_RECOGNIZED, options?.crit, parsedProtected, joseHeader)
      rejectZip(joseHeader)
      const { alg, enc } = joseHeader
      if (typeof alg !== "string" || !alg) raise(malformed("missing JWE Algorithm (alg) in JWE Header"))
      const selected = JWE[alg as string]
      if (jwe.encrypted_key === "" && (!selected || !isCekTransport(selected))) {
        raise(malformed("JWE Encrypted Key incorrect type"))
      }
      if (typeof enc !== "string" || !enc) {
        raise(malformed("missing JWE Encryption Algorithm (enc) in JWE Header"))
      }
      if (
        (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg as string)) ||
        (!keyManagementAlgorithms && (alg as string).startsWith("PBES2"))
      ) {
        raise(
          new AlgorithmNotAllowedError({
            parameter: "alg",
            algorithm: alg as string,
            message: "\"alg\" (Algorithm) Header Parameter value not allowed"
          })
        )
      }
      if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc as string)) {
        raise(
          new AlgorithmNotAllowedError({
            parameter: "enc",
            algorithm: enc as string,
            message: "\"enc\" (Encryption Algorithm) Header Parameter value not allowed"
          })
        )
      }
      const encEntry = jweEncryption(enc)
      let encryptedKey: Uint8Array | undefined
      if (jwe.encrypted_key !== undefined) {
        try {
          encryptedKey = decodeB64u(jwe.encrypted_key, "encrypted_key", malformed)
        } catch (e) {
          if (!selected || !isCekTransport(selected)) throw e
          encryptedKey = new Uint8Array()
        }
      }
      const entry = selected ?? jweAlgorithm(alg)
      if (isCekTransport(entry) && encryptedKey === undefined) encryptedKey = new Uint8Array()
      return { parsedProtected, ciphertext, iv, tag, additionalData, joseHeader, encEntry, entry, encryptedKey }
    })
    const resolved = typeof key === "function"
      ? yield* (key as KeyResolver<E, R>)(checked.parsedProtected as Header | undefined, jwe)
      : key
    const { entry, encEntry } = checked
    const k = yield* prepareKey(entry.mode === "direct-encryption" ? encEntry : entry, resolved, "decrypt")
    // Any key unwrapping failure other than a malformed input falls back to a
    // random CEK so that failures are indistinguishable (RFC 7516 section 11.5).
    const cek = yield* decryptKeyManagement(
      entry,
      encEntry,
      k,
      checked.encryptedKey,
      checked.joseHeader,
      options?.maxPBES2Count
    ).pipe(
      Effect.flatMap((cek) =>
        isCekTransport(entry) && cek instanceof Uint8Array && cek.byteLength << 3 !== encEntry.cekBits
          ? generateCek(encEntry)
          : Effect.succeed(cek)
      ),
      Effect.catchIf(
        (e) => e._tag === "DecryptionError" || e._tag === "PlatformError",
        () => generateCek(encEntry)
      )
    )
    const plaintext = yield* decryptContent(
      encEntry,
      cek,
      checked.ciphertext,
      checked.iv,
      checked.tag,
      checked.additionalData
    )
    const result: { -readonly [K in keyof DecryptResult]: DecryptResult[K] } = { plaintext }
    if (checked.parsedProtected) result.protectedHeader = checked.parsedProtected as Header
    if (jwe.aad !== undefined) {
      result.additionalAuthenticatedData = yield* attemptEncrypt(() => decodeB64u(jwe.aad!, "aad", malformed))
    }
    if (jwe.unprotected) result.sharedUnprotectedHeader = jwe.unprotected
    if (jwe.header) result.unprotectedHeader = jwe.header
    return result
  })

/**
 * Decrypts a JWE in compact serialization.
 *
 * @stability unstable
 * @category decryption
 * @since 4.0.0
 */
export const decryptCompact = <E = never, R = never>(
  jwe: string | Uint8Array,
  key: Key | KeyResolver<E, R>,
  options?: DecryptOptions
): Effect.Effect<DecryptResult, DecryptError | E, Crypto.Crypto | R> =>
  Effect.suspend(() => {
    const input = jwe instanceof Uint8Array ? new TextDecoder().decode(jwe) : jwe
    if (typeof input !== "string") return Effect.fail(malformed("Compact JWE must be a string or Uint8Array"))
    const parts = input.split(".")
    if (parts.length !== 5) return Effect.fail(malformed("Invalid Compact JWE"))
    const [protectedHeader, encryptedKey, iv, ciphertext, tag] = parts
    const flattened: { -readonly [K in keyof Flattened]: Flattened[K] } = { ciphertext, protected: protectedHeader }
    if (iv) flattened.iv = iv
    if (tag) flattened.tag = tag
    if (encryptedKey) flattened.encrypted_key = encryptedKey
    return decryptJwe(flattened, options, key)
  })

/**
 * Decrypts a JWE in flattened JSON serialization.
 *
 * @stability unstable
 * @category decryption
 * @since 4.0.0
 */
export const decryptFlattened = <E = never, R = never>(
  jwe: Flattened,
  key: Key | KeyResolver<E, R>,
  options?: DecryptOptions
): Effect.Effect<DecryptResult, DecryptError | E, Crypto.Crypto | R> =>
  Effect.suspend(() => {
    if (!isObject(jwe)) return Effect.fail(malformed("Flattened JWE must be an object"))
    return Effect.flatMap(
      attemptEncrypt(() => {
        snapshotShared(jwe)
        checkRecipient(jwe)
      }),
      () => decryptJwe(jwe, options, key)
    )
  })

/**
 * Decrypts a JWE in general JSON serialization, succeeding with the first
 * recipient that decrypts.
 *
 * @stability unstable
 * @category decryption
 * @since 4.0.0
 */
export const decryptGeneral = <E = never, R = never>(
  jwe: General,
  key: Key | KeyResolver<E, R>,
  options?: DecryptOptions
): Effect.Effect<DecryptResult, DecryptError | E, Crypto.Crypto | R> =>
  Effect.gen(function*() {
    if (!isObject(jwe)) return yield* Effect.fail(malformed("General JWE must be an object"))
    const { recipients, ...shared } = jwe as unknown as Record<string, unknown>
    if (!Array.isArray(recipients) || !recipients.every(isObject)) {
      return yield* Effect.fail(malformed("JWE Recipients missing or incorrect type"))
    }
    if (!recipients.length) return yield* Effect.fail(malformed("JWE Recipients has no members"))
    yield* attemptEncrypt(() => snapshotShared(shared))
    for (const recipient of recipients) {
      const candidate = { ...shared, ...recipient } as unknown as Flattened
      const checked = yield* Effect.result(attemptEncrypt(() => checkRecipient(candidate as any)))
      if (checked._tag === "Failure") continue
      const result = yield* Effect.result(decryptJwe(candidate, options, key))
      if (result._tag === "Success") return result.success
    }
    return yield* Effect.fail(decryptionFailed())
  })
