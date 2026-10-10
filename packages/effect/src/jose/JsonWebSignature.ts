/**
 * Signs and verifies JSON Web Signatures (RFC 7515) in compact, flattened
 * JSON, and general JSON serializations, including unencoded payloads
 * (RFC 7797).
 *
 * Verification always requires the token's `alg` header to be compatible with
 * the key, and callers can restrict accepted algorithms with the `algorithms`
 * option. The `none` algorithm is never accepted.
 *
 * @stability unstable
 * @since 4.0.0
 */
import * as Context from "../Context.ts"
import * as Crypto from "../Crypto.ts"
import * as Effect from "../Effect.ts"
import * as Layer from "../Layer.ts"
import * as Redacted from "../Redacted.ts"
import * as Schema from "../Schema.ts"
import { jwsAlgorithm } from "./internal/algorithms.ts"
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
  JWS_RECOGNIZED,
  maxTokenLength,
  parseHeader,
  provideCrypto,
  raise,
  readToken,
  serializeHeader,
  validateAlgorithms,
  validateB64,
  validateCrit
} from "./internal/shared.ts"
import type * as JsonWebAlgorithm from "./JsonWebAlgorithm.ts"
import { AlgorithmNotAllowedError } from "./JsonWebAlgorithm.ts"
import { checkModulusLength, type KeyError, prepareKey, rawKey } from "./JsonWebKey.ts"

/**
 * Error raised when a JWS is structurally invalid: the wrong number of
 * segments, segments that are not base64url, a protected header that is not a
 * JSON object, a missing `alg`, or an invalid `crit` or `b64` header.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class MalformedJwsError
  extends Schema.TaggedError<MalformedJwsError>("effect/jose/JsonWebSignature/MalformedJwsError")(
    "MalformedJwsError",
    { message: Schema.String }
  )
{}

/**
 * Error raised when a JWS signature does not match its payload and key.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class SignatureVerificationError extends Schema.TaggedError<SignatureVerificationError>(
  "effect/jose/JsonWebSignature/SignatureVerificationError"
)("SignatureVerificationError", { message: Schema.String }) {}

/**
 * Error raised when a JWS lists a critical (`crit`) extension header
 * parameter that the caller has not declared as understood.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class UnsupportedJwsHeaderError
  extends Schema.TaggedError<UnsupportedJwsHeaderError>("effect/jose/JsonWebSignature/UnsupportedJwsHeaderError")(
    "UnsupportedJwsHeaderError",
    { message: Schema.String }
  )
{}

/**
 * Error raised when a compact JWS is longer than `maxTokenLength`, before any
 * decoding or parsing.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class JwsTooLargeError
  extends Schema.TaggedError<JwsTooLargeError>("effect/jose/JsonWebSignature/JwsTooLargeError")(
    "JwsTooLargeError",
    { message: Schema.String, length: Schema.Number, maxLength: Schema.Number }
  )
{}

/**
 * Failures from producing a JWS.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type SignError = MalformedJwsError | UnsupportedJwsHeaderError | KeyError

/**
 * Failures from verifying a JWS.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type VerifyError = SignError | AlgorithmNotAllowedError | SignatureVerificationError | JwsTooLargeError

/**
 * Schema for unpadded base64url text, the `BASE64URL` encoding JOSE uses for
 * every binary member (RFC 7515 section 2).
 *
 * @stability unstable
 * @category schemas
 * @since 4.0.0
 */
export const Base64Url = Schema.String.check(
  Schema.isPattern(/^[A-Za-z0-9_-]*$/, { expected: "unpadded base64url text" })
).pipe(Schema.brand("~effect/jose/Base64Url"))

/**
 * Unpadded base64url text.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Base64Url = typeof Base64Url.Type

/**
 * Schema for a JWS in compact serialization: base64url header and signature
 * around a payload with no `.`.
 *
 * **Details**
 *
 * The brand records the format, not that the token was verified. Functions
 * that read tokens accept any string, since incoming tokens are untrusted;
 * decode with this schema to obtain a branded value at a boundary.
 *
 * @stability unstable
 * @category schemas
 * @since 4.0.0
 */
export const Compact = Schema.String.check(
  Schema.isPattern(/^[A-Za-z0-9_-]+\.[^.]*\.[A-Za-z0-9_-]+$/, { expected: "a JWS in compact serialization" })
).pipe(Schema.brand("~effect/jose/JsonWebSignature/Compact"))

/**
 * A JWS in compact serialization.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Compact = typeof Compact.Type

/**
 * A token to read: a string, its UTF-8 bytes, or a `Redacted` string such as
 * the value from `HttpApiSecurity.bearer`.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type TokenInput = string | Uint8Array | Redacted.Redacted<string>

const malformed = (message: string) => new MalformedJwsError({ message })
const unsupportedHeader = (message: string) => new UnsupportedJwsHeaderError({ message })
const attemptSign = attemptWith<SignError>()
const attempt = attemptWith<VerifyError>()

/**
 * Header parameters of a JWS.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface Header {
  readonly alg?: JsonWebAlgorithm.SignatureAlgorithm | undefined
  readonly kid?: string | undefined
  readonly typ?: string | undefined
  readonly cty?: string | undefined
  readonly crit?: ReadonlyArray<string> | undefined
  readonly b64?: boolean | undefined
  readonly jku?: string | undefined
  readonly jwk?: Crypto.JwkData | undefined
  readonly x5u?: string | undefined
  readonly x5c?: ReadonlyArray<string> | undefined
  readonly x5t?: string | undefined
  readonly "x5t#S256"?: string | undefined
  readonly [parameter: string]: unknown
}

/**
 * A JWS in flattened JSON serialization.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface Flattened {
  readonly protected?: string | undefined
  readonly header?: Header | undefined
  readonly payload: string | Uint8Array
  readonly signature: string
}

/**
 * A JWS in general JSON serialization.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface General {
  readonly payload: string
  readonly signatures: ReadonlyArray<Omit<Flattened, "payload">>
}

/**
 * A flattened JWS produced by `signFlattened`, with its base64url
 * members branded.
 *
 * **Details**
 *
 * `payload` is base64url text, or the raw payload when the protected header
 * sets `b64: false`.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface SignedFlattened extends Flattened {
  readonly protected?: Base64Url | undefined
  readonly payload: string
  readonly signature: Base64Url
}

/**
 * A general JWS produced by `signGeneral`, with its base64url members
 * branded.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface SignedGeneral extends General {
  readonly signatures: ReadonlyArray<Omit<SignedFlattened, "payload">>
}

/**
 * A key accepted by JWS operations: a `Crypto.Key`, raw secret bytes for HMAC
 * algorithms, or a JSON Web Key.
 *
 * **Gotchas**
 *
 * A JSON Web Key is imported on every call. To avoid repeated imports,
 * import it once with `importJwk` from the `JsonWebKey` service and pass the
 * resulting key, or provide `JsonWebKey.layerKeyCache`.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Key =
  | Crypto.Key
  | Uint8Array
  | Crypto.JwkData
  | Redacted.Redacted<Uint8Array>
  | Redacted.Redacted<Crypto.JwkData>

/**
 * Selects a verification key from a token's headers.
 *
 * **When to use**
 *
 * Use when the key depends on the token, for example by looking up `kid` in a
 * JSON Web Key Set.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type KeyResolver<E = never, R = never> = (
  protectedHeader: Header | undefined,
  token: Flattened
) => Effect.Effect<Key | KeyCandidates, E, R>

/**
 * Several keys a {@link KeyResolver} returns for verification to try in
 * order.
 *
 * **Details**
 *
 * Verification succeeds with the first candidate whose signature verifies.
 * Resolvers only return candidates when the caller opted into it, for example
 * with `multipleMatches: "tryEach"` on a key set.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type KeyCandidates = readonly [Key, ...Array<Key>]

/**
 * The result of a successful verification.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface VerifyResult {
  readonly payload: Uint8Array
  readonly protectedHeader?: Header | undefined
  readonly unprotectedHeader?: Header | undefined
}

/**
 * Options for JWS verification.
 *
 * **Details**
 *
 * `algorithms` restricts the accepted `alg` header values. `crit` maps
 * extension header names the caller understands to whether they must be
 * integrity protected; `b64` is always understood.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface VerifyOptions {
  readonly algorithms?: ReadonlyArray<JsonWebAlgorithm.SignatureAlgorithm> | undefined
  readonly crit?: Readonly<Record<string, boolean>> | undefined
  readonly maxTokenLength?: number | undefined
}

/**
 * Verification options with the accepted algorithms stated, as required for
 * keys that do not determine a single algorithm.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface VerifyOptionsWithAlgorithms extends VerifyOptions {
  readonly algorithms: ReadonlyArray<JsonWebAlgorithm.SignatureAlgorithm>
}

/**
 * The options a verify function requires for a given key: `algorithms` is
 * optional with a `Crypto.Key` and required otherwise.
 *
 * **Details**
 *
 * A `Crypto.Key` is bound to one algorithm. With raw secrets, JSON Web Keys,
 * and key resolvers the token's `alg` header would otherwise choose among
 * compatible algorithms, so the accepted algorithms must be stated
 * (RFC 8725 section 3.1).
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type OptionsFor<K, O extends VerifyOptions = VerifyOptions> = [K] extends [Crypto.Key] ? O
  : O & { readonly algorithms: ReadonlyArray<JsonWebAlgorithm.SignatureAlgorithm> }

/**
 * The failures a key resolver adds.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type ResolverError<K> = 0 extends 1 & K ? never : K extends KeyResolver<infer E, infer _R> ? E : never

/**
 * The services a key resolver requires.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type ResolverServices<K> = 0 extends 1 & K ? never : K extends KeyResolver<infer _E, infer R> ? R : never

/**
 * Signature of the {@link JsonWebSignature} verify methods.
 *
 * @see {@link OptionsFor} for when `algorithms` is required
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface Verify<Input> {
  <K extends Key | KeyResolver<any, any>>(
    jws: Input,
    key: K,
    ...options: [K] extends [Crypto.Key] ? [options?: VerifyOptions] : [options: OptionsFor<K>]
  ): Effect.Effect<VerifyResult, VerifyError | ResolverError<K>, ResolverServices<K>>
}

/**
 * Options for producing one JWS signature.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface SignOptions {
  readonly key: Key
  readonly protectedHeader?: Header | undefined
  readonly unprotectedHeader?: Header | undefined
  readonly crit?: Readonly<Record<string, boolean>> | undefined
}

const cryptoService = Effect.service(Crypto.Crypto)

const toBytes = (payload: Uint8Array | string): Uint8Array =>
  typeof payload === "string" ? encoder.encode(payload) : payload

interface Signed {
  readonly jws: { protected?: Base64Url; header?: Header; payload: string; signature: Base64Url }
  readonly b64: boolean
  readonly payloadBytes: Uint8Array
}

const createSignature = Effect.fnUntraced(function*(
  payload: Uint8Array,
  options: SignOptions,
  rejectUnencoded?: () => void
) {
  const prepared = yield* attemptSign(() => {
    let protectedHeader: Record<string, unknown> | undefined
    let protectedString = ""
    if (options.protectedHeader !== undefined) {
      const [parsed, serialized] = serializeHeader(malformed, options.protectedHeader)
      protectedHeader = parsed
      protectedString = b64u(serialized)
    }
    const unprotectedHeader = options.unprotectedHeader === undefined
      ? undefined
      : serializeHeader(malformed, options.unprotectedHeader)[0]
    if (!protectedHeader && !unprotectedHeader) {
      raise(malformed("either a protected or an unprotected header must be provided"))
    }
    if (!isDisjoint(protectedHeader, unprotectedHeader)) {
      raise(malformed("JWS Protected and JWS Unprotected Header Parameter names must be disjoint"))
    }
    const joseHeader = { ...protectedHeader, ...unprotectedHeader }
    const b64 = validateB64(
      malformed,
      protectedHeader ?? {},
      validateCrit(malformed, unsupportedHeader, JWS_RECOGNIZED, options.crit, protectedHeader, joseHeader)
    )
    if (!b64) rejectUnencoded?.()
    const alg = joseHeader.alg
    if (typeof alg !== "string" || !alg) {
      raise(malformed("JWS \"alg\" (Algorithm) Header Parameter missing or invalid"))
    }
    const entry = jwsAlgorithm(alg)
    let payloadString = ""
    let signingPayload = payload
    if (b64) {
      payloadString = b64u(payload)
      signingPayload = ascii(payloadString)!
    }
    const protectedBytes = ascii(protectedString)!
    const data = concat(protectedBytes, Uint8Array.of(0x2e), signingPayload)
    return { entry, data, protectedHeader, protectedString, unprotectedHeader, b64, payloadString }
  })
  const { entry } = prepared
  const key = yield* rawKey(yield* prepareKey(entry, options.key, "sign"), entry.key!, "sign")
  if (entry.minRsaBits) yield* attemptSign(() => checkModulusLength(entry.alg, key))
  const crypto = yield* cryptoService
  const signature = yield* crypto.sign(entry.signing, key, prepared.data)
  const jws: Signed["jws"] = { payload: prepared.payloadString, signature: b64u(signature) as Base64Url }
  if (prepared.protectedHeader) jws.protected = prepared.protectedString as Base64Url
  if (prepared.unprotectedHeader) jws.header = prepared.unprotectedHeader as Header
  return { jws, b64: prepared.b64, payloadBytes: payload } satisfies Signed
})

/** @internal */
export const signCompactInternal = (
  payload: Uint8Array | string,
  options: Omit<SignOptions, "unprotectedHeader"> & { readonly protectedHeader: Header },
  rejectUnencoded?: () => void
): Effect.Effect<Redacted.Redacted<Compact>, SignError, Crypto.Crypto> =>
  Effect.flatMap(createSignature(toBytes(payload), options, rejectUnencoded), ({ b64, jws }) => {
    if (!b64) {
      const raw = typeof payload === "string" ? payload : new TextDecoder().decode(payload)
      if (ascii(raw) === undefined || raw.includes(".")) {
        return Effect.fail(
          malformed("JWS Compact Serialization payload must use only ASCII characters other than \".\"")
        )
      }
      return Effect.succeed(Redacted.make(`${jws.protected}.${raw}.${jws.signature}` as Compact))
    }
    return Effect.succeed(Redacted.make(`${jws.protected}.${jws.payload}.${jws.signature}` as Compact))
  })

const signFlattened = (
  payload: Uint8Array | string,
  options: SignOptions
): Effect.Effect<SignedFlattened, SignError, Crypto.Crypto> =>
  Effect.map(
    createSignature(toBytes(payload), options),
    ({ b64, jws, payloadBytes }) => b64 ? jws : { ...jws, payload: new TextDecoder().decode(payloadBytes) }
  )

const signGeneral = Effect.fnUntraced(function*(
  payload: Uint8Array | string,
  signers: ReadonlyArray<SignOptions>
): Effect.fn.Return<SignedGeneral, SignError, Crypto.Crypto> {
  if (signers.length === 0) return yield* Effect.fail(malformed("at least one signature must be added"))
  const bytes = toBytes(payload)
  const signatures: Array<Omit<SignedFlattened, "payload">> = []
  let b64: boolean | undefined
  let encoded = ""
  for (const signer of signers) {
    const signed = yield* createSignature(bytes, signer)
    if (b64 === undefined) {
      b64 = signed.b64
      encoded = signed.b64 ? signed.jws.payload : new TextDecoder().decode(bytes)
    } else if (b64 !== signed.b64) {
      return yield* Effect.fail(malformed("inconsistent use of JWS Unencoded Payload (RFC7797)"))
    }
    const { payload: _, ...rest } = signed.jws
    signatures.push(rest)
  }
  return { payload: encoded, signatures }
})

const encodeJsonUnencodedPayload = (payload: string): Uint8Array => {
  const invalid = /[\p{Cs}\p{Cn}]/u.exec(payload)?.[0]
  if (invalid !== undefined) {
    raise(malformed(
      /\p{Cs}/u.test(invalid)
        ? "JWS Payload must be a well-formed Unicode string"
        : "JWS Payload must not contain unassigned Unicode code points"
    ))
  }
  return encoder.encode(payload)
}

const encodeCompactUnencodedPayload = (payload: string): Uint8Array =>
  ascii(payload) ?? raise(malformed("JWS Compact Serialization payload must use only ASCII characters"))

const snapshot = (jws: Record<string, unknown>): Flattened => {
  const encodedProtected = jws.protected
  const header = jws.header
  const payload = jws.payload
  const signature = jws.signature
  if (encodedProtected === undefined && header === undefined) {
    raise(malformed("Flattened JWS must have either of the \"protected\" or \"header\" members"))
  }
  if (encodedProtected !== undefined && typeof encodedProtected !== "string") {
    raise(malformed("JWS Protected Header incorrect type"))
  }
  if (payload === undefined) raise(malformed("JWS Payload missing"))
  if (typeof signature !== "string") raise(malformed("JWS Signature missing or incorrect type"))
  if (header !== undefined && !isObject(header)) raise(malformed("JWS Unprotected Header incorrect type"))
  const out: Record<string, unknown> = {
    payload: payload instanceof Uint8Array ? new Uint8Array(payload) : payload,
    signature
  }
  if (encodedProtected !== undefined) out.protected = encodedProtected
  if (header !== undefined) out.header = { ...header as object }
  return out as unknown as Flattened
}

const verifySignature = <E, R>(
  jws: Flattened,
  options: VerifyOptions | undefined,
  key: Key | KeyResolver<E, R>,
  encodeUnencoded: (payload: string) => Uint8Array,
  parsedProtected?: Record<string, unknown>
): Effect.Effect<VerifyResult & { readonly b64: boolean }, VerifyError | E, Crypto.Crypto | R> =>
  Effect.gen(function*() {
    if (options?.algorithms === undefined && (typeof key === "function" || !isCryptoKey(key))) {
      return yield* Effect.die(new TypeError("\"algorithms\" is required unless the key is a Crypto.Key"))
    }
    const checked = yield* attempt(() => {
      const algorithms = validateAlgorithms("algorithms", options?.algorithms)
      const protectedHeader = parsedProtected ??
        (jws.protected === undefined
          ? {}
          : parseHeader(jws.protected, malformed, "JWS Protected Header is invalid"))
      if (!isDisjoint(protectedHeader, jws.header)) {
        raise(malformed("JWS Protected and JWS Unprotected Header Parameter names must be disjoint"))
      }
      const joseHeader: Record<string, unknown> = { ...protectedHeader, ...jws.header }
      const b64 = validateB64(
        malformed,
        protectedHeader,
        validateCrit(malformed, unsupportedHeader, JWS_RECOGNIZED, options?.crit, protectedHeader, joseHeader)
      )
      const alg = joseHeader.alg
      if (typeof alg !== "string" || !alg) {
        raise(malformed("JWS \"alg\" (Algorithm) Header Parameter missing or invalid"))
      }
      if (algorithms && !algorithms.has(alg as string)) {
        raise(
          new AlgorithmNotAllowedError({
            parameter: "alg",
            algorithm: alg as string,
            message: "\"alg\" (Algorithm) Header Parameter value not allowed"
          })
        )
      }
      const input = jws.payload
      if (b64) {
        if (typeof input !== "string") raise(malformed("JWS Payload must be a string"))
      } else if (typeof input !== "string" && !(input instanceof Uint8Array)) {
        raise(malformed("JWS Payload must be a string or an Uint8Array instance"))
      }
      const signingPayload: string | Uint8Array = b64 || typeof input !== "string" ? input : encodeUnencoded(input)
      return { protectedHeader, b64, alg: alg as string, signingPayload }
    })
    const resolved: unknown = typeof key === "function"
      ? yield* (key as KeyResolver<E, R>)(
        jws.protected === undefined ? undefined : checked.protectedHeader as Header,
        jws
      )
      : key
    const prepared = yield* attempt(() => {
      const entry = jwsAlgorithm(checked.alg)
      const payloadPart = typeof checked.signingPayload === "string"
        ? ascii(checked.signingPayload) ?? raise(malformed("The payload is not a valid base64url string"))
        : checked.signingPayload
      const data = concat(
        jws.protected !== undefined ? ascii(jws.protected) ?? new Uint8Array() : new Uint8Array(),
        Uint8Array.of(0x2e),
        payloadPart
      )
      const signature = decodeB64u(jws.signature, "signature", malformed)
      return { entry, data, signature }
    })
    const { entry } = prepared
    const crypto = yield* cryptoService
    const verifyWith = (candidate: unknown) =>
      Effect.gen(function*() {
        const k = yield* rawKey(yield* prepareKey(entry, candidate, "verify"), entry.key!, "verify")
        if (entry.minRsaBits) yield* attempt(() => checkModulusLength(entry.alg, k))
        const verified = yield* Effect.orElseSucceed(
          crypto.verify(entry.signing, k, prepared.signature, prepared.data),
          () => false
        )
        if (!verified) {
          return yield* Effect.fail(new SignatureVerificationError({ message: "signature verification failed" }))
        }
      })
    if (!Array.isArray(resolved)) {
      yield* verifyWith(resolved)
    } else {
      // Candidates are tried in order. When none verifies, report a signature
      // failure if any candidate was usable, otherwise the first key error.
      let firstError: VerifyError | undefined
      let attempted = false
      let verified = false
      for (const candidate of resolved) {
        const result = yield* Effect.result(verifyWith(candidate))
        if (result._tag === "Success") {
          verified = true
          break
        }
        if (result.failure._tag === "SignatureVerificationError") attempted = true
        firstError ??= result.failure
      }
      if (!verified) {
        return yield* Effect.fail(
          attempted ? new SignatureVerificationError({ message: "signature verification failed" }) : firstError!
        )
      }
    }
    const payload = typeof checked.signingPayload === "string"
      ? yield* attempt(() => decodeB64u(checked.signingPayload as string, "payload", malformed))
      : checked.signingPayload
    const result: { payload: Uint8Array; protectedHeader?: Header; unprotectedHeader?: Header; b64: boolean } = {
      payload,
      b64: checked.b64
    }
    if (jws.protected !== undefined) result.protectedHeader = checked.protectedHeader as Header
    if (jws.header !== undefined) result.unprotectedHeader = jws.header
    return result
  })

/** @internal */
export const verifyCompactInternal = <E, R>(
  jws: TokenInput,
  key: Key | KeyResolver<E, R>,
  options?: VerifyOptions
): Effect.Effect<VerifyResult & { readonly b64: boolean }, VerifyError | E, Crypto.Crypto | R> =>
  Effect.suspend(() => {
    const input = readToken(jws)
    if (input === undefined) return Effect.die(new TypeError("Compact JWS must be a string, Uint8Array, or Redacted"))
    const limit = maxTokenLength(options?.maxTokenLength)
    if (input.length > limit) {
      return Effect.fail(
        new JwsTooLargeError({
          message: `Compact JWS is ${input.length} characters, more than the limit of ${limit}`,
          length: input.length,
          maxLength: limit
        })
      )
    }
    const parts = input.split(".")
    if (parts.length !== 3) return Effect.fail(malformed("Invalid Compact JWS"))
    return verifySignature(
      { protected: parts[0], payload: parts[1], signature: parts[2] },
      options,
      key,
      encodeCompactUnencodedPayload
    )
  })

const verifyCompact = <E, R>(
  jws: TokenInput,
  key: Key | KeyResolver<E, R>,
  options?: VerifyOptions
): Effect.Effect<VerifyResult, VerifyError | E, Crypto.Crypto | R> =>
  Effect.map(verifyCompactInternal(jws, key, options), ({ b64: _, ...result }) => result)

const verifyFlattened = <E, R>(
  jws: Flattened,
  key: Key | KeyResolver<E, R>,
  options?: VerifyOptions
): Effect.Effect<VerifyResult, VerifyError | E, Crypto.Crypto | R> =>
  Effect.suspend(() => {
    if (!isObject(jws)) return Effect.fail(malformed("Flattened JWS must be an object"))
    return Effect.flatMap(
      attempt(() => snapshot(jws)),
      (snap) =>
        Effect.map(
          verifySignature(snap, options, key, encodeJsonUnencodedPayload),
          ({ b64: _, ...result }) => result
        )
    )
  })

const verifyGeneral = <E, R>(
  jws: General,
  key: Key | KeyResolver<E, R>,
  options?: VerifyOptions
): Effect.Effect<VerifyResult, VerifyError | E, Crypto.Crypto | R> =>
  Effect.gen(function*() {
    if (!isObject(jws)) return yield* Effect.fail(malformed("General JWS must be an object"))
    const { signatures, payload } = jws as unknown as Record<string, unknown>
    if (!Array.isArray(signatures) || !signatures.every(isObject)) {
      return yield* Effect.fail(malformed("JWS Signatures missing or incorrect type"))
    }
    if (payload === undefined) {
      return yield* Effect.fail(new SignatureVerificationError({ message: "signature verification failed" }))
    }
    const candidates: Array<readonly [Flattened, Record<string, unknown>, number]> = []
    for (const signature of signatures) {
      try {
        const snap = snapshot({ ...signature, payload })
        const protectedHeader = snap.protected === undefined
          ? {}
          : parseHeader(snap.protected, malformed, "JWS Protected Header is invalid")
        const { b64, crit } = protectedHeader
        const mode = Array.isArray(crit) && crit.includes("b64")
          ? typeof b64 === "boolean" ? (b64 ? 1 : 2) : 0
          : 1
        candidates.push([snap, protectedHeader, mode])
      } catch {
        // invalid signatures are skipped
      }
    }
    let modes = 0
    for (const [, , mode] of candidates) {
      modes |= mode
      if (modes === 3) return yield* Effect.fail(malformed("inconsistent use of JWS Unencoded Payload (RFC7797)"))
    }
    for (const [snap, protectedHeader] of candidates) {
      const result = yield* Effect.result(
        verifySignature(snap, options, key, encodeJsonUnencodedPayload, protectedHeader)
      )
      if (result._tag === "Success") {
        const { b64: _, ...rest } = result.success
        return rest
      }
    }
    return yield* Effect.fail(new SignatureVerificationError({ message: "signature verification failed" }))
  })

/**
 * Decodes the protected header of a compact JWS or JWE without verifying it.
 *
 * **Gotchas**
 *
 * The returned header is untrusted until the token is verified.
 *
 * @stability unstable
 * @category decoding
 * @since 4.0.0
 */
export const decodeProtectedHeader = (token: TokenInput): Effect.Effect<Header, MalformedJwsError> =>
  attemptWith<MalformedJwsError>()(() => {
    const input = readToken(token)
    if (input === undefined) throw new TypeError("Token must be a string, Uint8Array, or Redacted")
    const encoded = input.split(".")[0]
    return parseHeader(encoded, malformed, "Invalid Token or Protected Header formatting") as Header
  })

/**
 * Resolves the verification key from the token's own `jwk` protected header
 * parameter (RFC 7515 section 4.1.3).
 *
 * **When to use**
 *
 * Use when the signer presents its own public key, as in protocols such as
 * DPoP proofs, and trust is established separately, for example by comparing
 * the key's thumbprint with a bound value.
 *
 * **Gotchas**
 *
 * A valid signature only proves possession of the embedded key, not who owns
 * it. The `jwk` must be in the protected header, must be a public key, and
 * cannot be used with symmetric algorithms.
 *
 * @stability unstable
 * @category key resolvers
 * @since 4.0.0
 */
export const embeddedKey: KeyResolver<MalformedJwsError> = (protectedHeader) =>
  Effect.suspend(() => {
    const jwk = protectedHeader?.jwk as unknown
    if (!isObject(jwk)) {
      return Effect.fail(malformed("\"jwk\" (JSON Web Key) protected Header Parameter must be a JSON object"))
    }
    if (jwk.kty === "oct" || jwk.d !== undefined) {
      return Effect.fail(malformed("\"jwk\" (JSON Web Key) Header Parameter must be a public key"))
    }
    return Effect.succeed(jwk as Crypto.JwkData)
  })

/**
 * Signs and verifies JSON Web Signatures with the `Crypto` service provided
 * to {@link layer}.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface JsonWebSignature {
  /**
   * Produces a JWS in compact serialization.
   *
   * **Details**
   *
   * Unencoded payloads (`b64: false`) must contain only ASCII characters other
   * than `.` to be representable in compact serialization.
   */
  readonly signCompact: (
    payload: Uint8Array | string,
    options: Omit<SignOptions, "unprotectedHeader"> & { readonly protectedHeader: Header }
  ) => Effect.Effect<Redacted.Redacted<Compact>, SignError>

  /**
   * Produces a JWS in flattened JSON serialization.
   */
  readonly signFlattened: (
    payload: Uint8Array | string,
    options: SignOptions
  ) => Effect.Effect<SignedFlattened, SignError>

  /**
   * Produces a JWS in general JSON serialization with one signature per signer.
   *
   * **Gotchas**
   *
   * All signers must agree on whether the payload is base64url encoded.
   */
  readonly signGeneral: (
    payload: Uint8Array | string,
    signers: ReadonlyArray<SignOptions>
  ) => Effect.Effect<SignedGeneral, SignError>

  /**
   * Verifies a JWS in compact serialization.
   *
   * **Details**
   *
   * `key` may be a key or a {@link KeyResolver}. The result contains the
   * decoded payload bytes and the protected header.
   */
  readonly verifyCompact: Verify<TokenInput>

  /**
   * Verifies a JWS in flattened JSON serialization.
   */
  readonly verifyFlattened: Verify<Flattened>

  /**
   * Verifies a JWS in general JSON serialization, succeeding with the first
   * signature that verifies.
   */
  readonly verifyGeneral: Verify<General>
}

/**
 * The {@link JsonWebSignature} service.
 *
 * @stability unstable
 * @category services
 * @since 4.0.0
 */
export const JsonWebSignature: Context.Service<
  JsonWebSignature,
  JsonWebSignature
> = Context.Service("effect/jose/JsonWebSignature")

/**
 * Creates the {@link JsonWebSignature} service with the current `Crypto`
 * service.
 *
 * @stability unstable
 * @category constructors
 * @since 4.0.0
 */
export const make: Effect.Effect<JsonWebSignature, never, Crypto.Crypto> = Effect.map(
  Effect.service(Crypto.Crypto),
  (crypto) => {
    const provide = provideCrypto(crypto)
    return JsonWebSignature.of({
      signCompact: provide(signCompactInternal),
      signFlattened: provide(signFlattened),
      signGeneral: provide(signGeneral),
      verifyCompact: provide(verifyCompact),
      verifyFlattened: provide(verifyFlattened),
      verifyGeneral: provide(verifyGeneral)
    })
  }
)

/**
 * Provides the {@link JsonWebSignature} service, requiring `Crypto`.
 *
 * **Example** (Signing and verifying a compact JWS)
 *
 * ```ts
 * import { Effect } from "effect"
 * import { JsonWebSignature } from "effect/jose"
 *
 * const secret = new TextEncoder().encode("a-string-secret-at-least-256-bits-long")
 *
 * const program = Effect.gen(function*() {
 *   const jws = yield* JsonWebSignature.JsonWebSignature
 *   const token = yield* jws.signCompact("hello", { key: secret, protectedHeader: { alg: "HS256" } })
 *   const { payload } = yield* jws.verifyCompact(token, secret, { algorithms: ["HS256"] })
 *   return new TextDecoder().decode(payload)
 * })
 * ```
 *
 * @stability unstable
 * @category layers
 * @since 4.0.0
 */
export const layer: Layer.Layer<JsonWebSignature, never, Crypto.Crypto> = Layer.effect(JsonWebSignature, make)
