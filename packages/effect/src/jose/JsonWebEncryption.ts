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
import { isCekTransport, JWE, type JweEntry, jweAlgorithm, jweEncryption } from "./internal/algorithms.ts"
import * as internal from "./internal/jwe.ts"
import { prepareKey } from "./internal/key.ts"
import {
  ascii,
  attempt,
  b64u,
  decodeB64u,
  fail,
  failSync,
  isDisjoint,
  isObject,
  JWE_RECOGNIZED,
  parseHeader,
  serializeHeader,
  validateAlgorithms,
  validateCrit
} from "./internal/shared.ts"
import type { JoseError } from "./JoseError.ts"
import type * as JsonWebAlgorithm from "./JsonWebAlgorithm.ts"

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
  readonly recipients: ReadonlyArray<{ readonly header?: Header | undefined; readonly encrypted_key?: string | undefined }>
  readonly iv?: string | undefined
  readonly ciphertext: string
  readonly tag?: string | undefined
  readonly aad?: string | undefined
}

/**
 * A key accepted by JWE operations: a `Crypto.Key`, raw secret bytes for
 * symmetric algorithms, or a JSON Web Key.
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
export type KeyManagementParameters = internal.KeyManagementParameters

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

const toBytes = (input: Uint8Array | string): Uint8Array =>
  typeof input === "string" ? new TextEncoder().encode(input) : input

const checkDisjoint = (...headers: ReadonlyArray<object | undefined>) => {
  if (!isDisjoint(...headers)) {
    failSync(
      "JweInvalid",
      "JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint"
    )
  }
}

const rejectZip = (joseHeader: Record<string, unknown>) => {
  if (joseHeader.zip !== undefined) {
    failSync("NotSupported", "JWE \"zip\" (Compression Algorithm) Header Parameter is not supported")
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
    failSync("JweInvalid", "either a protected, shared unprotected, or unprotected header must be provided")
  }
  const protectedHeader = options.protectedHeader && serializeHeader("JweInvalid", options.protectedHeader)[0]
  const unprotectedHeader = options.unprotectedHeader && serializeHeader("JweInvalid", options.unprotectedHeader)[0]
  const sharedUnprotectedHeader = options.sharedUnprotectedHeader &&
    serializeHeader("JweInvalid", options.sharedUnprotectedHeader)[0]
  checkDisjoint(protectedHeader, unprotectedHeader, sharedUnprotectedHeader)
  const joseHeader = { ...protectedHeader, ...unprotectedHeader, ...sharedUnprotectedHeader }
  validateCrit("JweInvalid", JWE_RECOGNIZED, options.crit, protectedHeader, joseHeader)
  rejectZip(joseHeader)
  const { alg, enc } = joseHeader
  if (typeof alg !== "string" || !alg) failSync("JweInvalid", "JWE \"alg\" (Algorithm) Header Parameter missing or invalid")
  if (typeof enc !== "string" || !enc) {
    failSync("JweInvalid", "JWE \"enc\" (Encryption Algorithm) Header Parameter missing or invalid")
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
  options: EncryptOptions
): Effect.Effect<Flattened, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    let { protectedHeader, unprotectedHeader } = checked
    const [cek, encryptedKey, parameters] = yield* internal.encryptKeyManagement(
      checked.entry,
      checked.enc,
      options.key,
      checked.joseHeader,
      options.cek,
      options.keyManagementParameters
    )
    if (parameters) {
      protectedHeader = protectedHeader ? { ...protectedHeader, ...parameters } : parameters
      yield* attempt(() => checkDisjoint(protectedHeader, unprotectedHeader, checked.sharedUnprotectedHeader))
    }
    const protectedString = protectedHeader ? b64u(JSON.stringify(protectedHeader)) : ""
    const aad = options.additionalAuthenticatedData
    const aadMember = aad?.byteLength ? b64u(aad) : undefined
    const additionalData = ascii(aadMember ? `${protectedString}.${aadMember}` : protectedString)!
    const { ciphertext, iv, tag } = yield* internal.encryptContent(
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
): Effect.Effect<Flattened, JoseError, Crypto.Crypto> =>
  Effect.flatMap(attempt(() => checkEncryptHeaders(options)), (checked) => encryptJwe(toBytes(plaintext), checked, options))

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
): Effect.Effect<string, JoseError, Crypto.Crypto> =>
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
): Effect.Effect<General, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    const { recipients } = options
    if (recipients.length === 0) return yield* fail("JweInvalid", "at least one recipient must be added")
    const multiple = recipients.length > 1
    const checkedRecipients = yield* attempt(() => {
      let enc: string | undefined
      return recipients.map((recipient) => {
        const checked = checkEncryptHeaders({
          protectedHeader: options.protectedHeader,
          sharedUnprotectedHeader: options.sharedUnprotectedHeader,
          unprotectedHeader: recipient.unprotectedHeader,
          crit: recipient.crit
        })
        if (multiple && !isCekTransport(checked.entry)) {
          failSync("JweInvalid", `"${checked.entry.alg}" alg may only have a single recipient`)
        }
        if (enc === undefined) enc = checked.enc.alg
        else if (enc !== checked.enc.alg) {
          failSync("JweInvalid", "JWE \"enc\" (Encryption Algorithm) Header Parameter must be the same for all recipients")
        }
        return checked
      })
    })
    const first = checkedRecipients[0]
    const cek = multiple ? yield* internal.generateCek(first.enc) : undefined
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
    })
    const out: Array<{ header?: Header; encrypted_key?: string }> = [{}]
    if (encrypted_key) out[0].encrypted_key = encrypted_key
    if (header) out[0].header = header
    for (let i = 1; i < recipients.length; i++) {
      const checked = checkedRecipients[i]
      const [, encryptedKey, parameters] = yield* internal.encryptKeyManagement(
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
        if (parameters) yield* attempt(() => checkDisjoint(checked.protectedHeader, merged, checked.sharedUnprotectedHeader))
        target.header = merged
      }
      out.push(target)
    }
    return { ...shared, recipients: out } as General
  })

const snapshotShared = (jwe: Record<string, unknown>) => {
  const { aad, ciphertext, iv, protected: encodedProtected, tag, unprotected } = jwe
  if (iv !== undefined && (typeof iv !== "string" || !iv)) failSync("JweInvalid", "JWE Initialization Vector incorrect type")
  if (typeof ciphertext !== "string") failSync("JweInvalid", "JWE Ciphertext missing or incorrect type")
  if (tag !== undefined && (typeof tag !== "string" || !tag)) failSync("JweInvalid", "JWE Authentication Tag incorrect type")
  if (encodedProtected !== undefined && typeof encodedProtected !== "string") {
    failSync("JweInvalid", "JWE Protected Header incorrect type")
  }
  if (aad !== undefined && (typeof aad !== "string" || !aad)) failSync("JweInvalid", "JWE AAD incorrect type")
  if (unprotected !== undefined && !isObject(unprotected)) {
    failSync("JweInvalid", "JWE Shared Unprotected Header incorrect type")
  }
}

const checkRecipient = (jwe: Record<string, unknown>) => {
  const { encrypted_key: encryptedKey, header } = jwe
  if (encryptedKey !== undefined && typeof encryptedKey !== "string") {
    failSync("JweInvalid", "JWE Encrypted Key incorrect type")
  }
  if (header !== undefined && !isObject(header)) failSync("JweInvalid", "JWE Per-Recipient Unprotected Header incorrect type")
  if (jwe.protected === undefined && header === undefined && jwe.unprotected === undefined) {
    failSync("JweInvalid", "JOSE Header missing")
  }
}

const decryptJwe = <E, R>(
  jwe: Flattened,
  options: DecryptOptions | undefined,
  key: Key | KeyResolver<E, R>
): Effect.Effect<DecryptResult, JoseError | E, Crypto.Crypto | R> =>
  Effect.gen(function*() {
    const checked = yield* attempt(() => {
      const parsedProtected = jwe.protected === undefined
        ? undefined
        : parseHeader(jwe.protected, "JweInvalid", "JWE Protected Header is invalid")
      const ciphertext = decodeB64u(jwe.ciphertext, "ciphertext", "JweInvalid")
      const iv = jwe.iv !== undefined ? decodeB64u(jwe.iv, "iv", "JweInvalid") : undefined
      const tag = jwe.tag !== undefined ? decodeB64u(jwe.tag, "tag", "JweInvalid") : undefined
      const additionalData = ascii((jwe.protected ?? "") + (jwe.aad !== undefined ? `.${jwe.aad}` : "")) ??
        failSync("JweInvalid", "The aad is not a valid base64url string")
      let joseHeader: Record<string, unknown>
      if (jwe.header !== undefined || jwe.unprotected !== undefined) {
        if (!isDisjoint(parsedProtected, jwe.header, jwe.unprotected)) {
          failSync(
            "JweInvalid",
            "JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint"
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
      validateCrit("JweInvalid", JWE_RECOGNIZED, options?.crit, parsedProtected, joseHeader)
      rejectZip(joseHeader)
      const { alg, enc } = joseHeader
      if (typeof alg !== "string" || !alg) failSync("JweInvalid", "missing JWE Algorithm (alg) in JWE Header")
      const selected = JWE[alg as string]
      if (jwe.encrypted_key === "" && (!selected || !isCekTransport(selected))) {
        failSync("JweInvalid", "JWE Encrypted Key incorrect type")
      }
      if (typeof enc !== "string" || !enc) failSync("JweInvalid", "missing JWE Encryption Algorithm (enc) in JWE Header")
      if (
        (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg as string)) ||
        (!keyManagementAlgorithms && (alg as string).startsWith("PBES2"))
      ) {
        failSync("AlgorithmNotAllowed", "\"alg\" (Algorithm) Header Parameter value not allowed")
      }
      if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc as string)) {
        failSync("AlgorithmNotAllowed", "\"enc\" (Encryption Algorithm) Header Parameter value not allowed")
      }
      const encEntry = jweEncryption(enc)
      let encryptedKey: Uint8Array | undefined
      if (jwe.encrypted_key !== undefined) {
        try {
          encryptedKey = decodeB64u(jwe.encrypted_key, "encrypted_key", "JweInvalid")
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
    const cek = yield* internal.decryptKeyManagement(
      entry,
      encEntry,
      k,
      checked.encryptedKey,
      checked.joseHeader,
      options?.maxPBES2Count
    ).pipe(
      Effect.flatMap((cek) =>
        isCekTransport(entry) && cek instanceof Uint8Array && cek.byteLength << 3 !== encEntry.cekBits
          ? internal.generateCek(encEntry)
          : Effect.succeed(cek)
      ),
      Effect.catchIf(
        (e) => e.reason !== "InvalidKey" && e.reason !== "JweInvalid" && e.reason !== "NotSupported" &&
          e.reason !== "InvalidArgument",
        () => internal.generateCek(encEntry)
      )
    )
    const plaintext = yield* internal.decryptContent(
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
      result.additionalAuthenticatedData = yield* attempt(() => decodeB64u(jwe.aad!, "aad", "JweInvalid"))
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
): Effect.Effect<DecryptResult, JoseError | E, Crypto.Crypto | R> =>
  Effect.suspend(() => {
    const input = jwe instanceof Uint8Array ? new TextDecoder().decode(jwe) : jwe
    if (typeof input !== "string") return fail("JweInvalid", "Compact JWE must be a string or Uint8Array")
    const parts = input.split(".")
    if (parts.length !== 5) return fail("JweInvalid", "Invalid Compact JWE")
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
): Effect.Effect<DecryptResult, JoseError | E, Crypto.Crypto | R> =>
  Effect.suspend(() => {
    if (!isObject(jwe)) return fail("JweInvalid", "Flattened JWE must be an object")
    return Effect.flatMap(
      attempt(() => {
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
): Effect.Effect<DecryptResult, JoseError | E, Crypto.Crypto | R> =>
  Effect.gen(function*() {
    if (!isObject(jwe)) return yield* fail("JweInvalid", "General JWE must be an object")
    const { recipients, ...shared } = jwe as unknown as Record<string, unknown>
    if (!Array.isArray(recipients) || !recipients.every(isObject)) {
      return yield* fail("JweInvalid", "JWE Recipients missing or incorrect type")
    }
    if (!recipients.length) return yield* fail("JweInvalid", "JWE Recipients has no members")
    yield* attempt(() => snapshotShared(shared))
    for (const recipient of recipients) {
      const candidate = { ...shared, ...recipient } as unknown as Flattened
      const checked = yield* Effect.result(attempt(() => checkRecipient(candidate as any)))
      if (checked._tag === "Failure") continue
      const result = yield* Effect.result(decryptJwe(candidate, options, key))
      if (result._tag === "Success") return result.success
    }
    return yield* fail("DecryptionFailed", "decryption operation failed")
  })
