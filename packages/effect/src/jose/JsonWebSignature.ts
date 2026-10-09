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
import * as Crypto from "../Crypto.ts"
import * as Effect from "../Effect.ts"
import { jwsAlgorithm } from "./internal/algorithms.ts"
import { checkModulusLength, prepareKey, rawKey } from "./internal/key.ts"
import {
  ascii,
  attempt,
  b64u,
  concat,
  decodeB64u,
  encoder,
  fail,
  failSync,
  isDisjoint,
  isObject,
  JWS_RECOGNIZED,
  mapCryptoError,
  parseHeader,
  serializeHeader,
  validateAlgorithms,
  validateB64,
  validateCrit
} from "./internal/shared.ts"
import type { JoseError } from "./JoseError.ts"
import type * as JsonWebAlgorithm from "./JsonWebAlgorithm.ts"

/**
 * Header parameters of a JWS.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface Header {
  readonly alg?: JsonWebAlgorithm.SignatureAlgorithm | (string & {}) | undefined
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
 * A key accepted by JWS operations: a `Crypto.Key`, raw secret bytes for HMAC
 * algorithms, or a JSON Web Key.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Key = Crypto.Key | Uint8Array | Crypto.JwkData

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
) => Effect.Effect<Key, E, R>

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
  readonly algorithms?: ReadonlyArray<string> | undefined
  readonly crit?: Readonly<Record<string, boolean>> | undefined
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
  readonly jws: { protected?: string; header?: Header; payload: string; signature: string }
  readonly b64: boolean
  readonly payloadBytes: Uint8Array
}

const createSignature = Effect.fnUntraced(function*(
  payload: Uint8Array,
  options: SignOptions,
  rejectUnencoded?: () => void
) {
  const prepared = yield* attempt(() => {
    let protectedHeader: Record<string, unknown> | undefined
    let protectedString = ""
    if (options.protectedHeader !== undefined) {
      const [parsed, serialized] = serializeHeader("JwsInvalid", options.protectedHeader)
      protectedHeader = parsed
      protectedString = b64u(serialized)
    }
    const unprotectedHeader = options.unprotectedHeader === undefined
      ? undefined
      : serializeHeader("JwsInvalid", options.unprotectedHeader)[0]
    if (!protectedHeader && !unprotectedHeader) {
      failSync("JwsInvalid", "either a protected or an unprotected header must be provided")
    }
    if (!isDisjoint(protectedHeader, unprotectedHeader)) {
      failSync("JwsInvalid", "JWS Protected and JWS Unprotected Header Parameter names must be disjoint")
    }
    const joseHeader = { ...protectedHeader, ...unprotectedHeader }
    const b64 = validateB64(
      protectedHeader ?? {},
      validateCrit("JwsInvalid", JWS_RECOGNIZED, options.crit, protectedHeader, joseHeader)
    )
    if (!b64) rejectUnencoded?.()
    const alg = joseHeader.alg
    if (typeof alg !== "string" || !alg) {
      failSync("JwsInvalid", "JWS \"alg\" (Algorithm) Header Parameter missing or invalid")
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
  if (entry.minRsaBits) yield* attempt(() => checkModulusLength(entry.alg, key))
  const crypto = yield* cryptoService
  const signature = yield* mapCryptoError(crypto.sign(entry.signing, key, prepared.data))
  const jws: Signed["jws"] = { payload: prepared.payloadString, signature: b64u(signature) }
  if (prepared.protectedHeader) jws.protected = prepared.protectedString
  if (prepared.unprotectedHeader) jws.header = prepared.unprotectedHeader as Header
  return { jws, b64: prepared.b64, payloadBytes: payload } satisfies Signed
})

/**
 * Produces a JWS in compact serialization.
 *
 * **Details**
 *
 * Unencoded payloads (`b64: false`) must contain only ASCII characters other
 * than `.` to be representable in compact serialization.
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
 *   const jws = yield* JsonWebSignature.signCompact("hello", {
 *     key: secret,
 *     protectedHeader: { alg: "HS256" }
 *   })
 *   const { payload } = yield* JsonWebSignature.verifyCompact(jws, secret, { algorithms: ["HS256"] })
 *   return new TextDecoder().decode(payload)
 * })
 * ```
 *
 * @stability unstable
 * @category signing
 * @since 4.0.0
 */
export const signCompact = (
  payload: Uint8Array | string,
  options: Omit<SignOptions, "unprotectedHeader"> & { readonly protectedHeader: Header },
  rejectUnencoded?: () => void
): Effect.Effect<string, JoseError, Crypto.Crypto> =>
  Effect.flatMap(createSignature(toBytes(payload), options, rejectUnencoded), ({ b64, jws }) => {
    if (!b64) {
      const raw = typeof payload === "string" ? payload : new TextDecoder().decode(payload)
      if (ascii(raw) === undefined || raw.includes(".")) {
        return fail("JwsInvalid", "JWS Compact Serialization payload must use only ASCII characters other than \".\"")
      }
      return Effect.succeed(`${jws.protected}.${raw}.${jws.signature}`)
    }
    return Effect.succeed(`${jws.protected}.${jws.payload}.${jws.signature}`)
  })

/**
 * Produces a JWS in flattened JSON serialization.
 *
 * @stability unstable
 * @category signing
 * @since 4.0.0
 */
export const signFlattened = (
  payload: Uint8Array | string,
  options: SignOptions
): Effect.Effect<Flattened, JoseError, Crypto.Crypto> =>
  Effect.map(
    createSignature(toBytes(payload), options),
    ({ b64, jws, payloadBytes }) => b64 ? jws : { ...jws, payload: new TextDecoder().decode(payloadBytes) }
  )

/**
 * Produces a JWS in general JSON serialization with one signature per signer.
 *
 * **Gotchas**
 *
 * All signers must agree on whether the payload is base64url encoded.
 *
 * @stability unstable
 * @category signing
 * @since 4.0.0
 */
export const signGeneral = Effect.fnUntraced(function*(
  payload: Uint8Array | string,
  signers: ReadonlyArray<SignOptions>
): Effect.fn.Return<General, JoseError, Crypto.Crypto> {
  if (signers.length === 0) return yield* fail("JwsInvalid", "at least one signature must be added")
  const bytes = toBytes(payload)
  const signatures: Array<Omit<Flattened, "payload">> = []
  let b64: boolean | undefined
  let encoded = ""
  for (const signer of signers) {
    const signed = yield* createSignature(bytes, signer)
    if (b64 === undefined) {
      b64 = signed.b64
      encoded = signed.b64 ? signed.jws.payload : new TextDecoder().decode(bytes)
    } else if (b64 !== signed.b64) {
      return yield* fail("JwsInvalid", "inconsistent use of JWS Unencoded Payload (RFC7797)")
    }
    const { payload: _, ...rest } = signed.jws
    signatures.push(rest)
  }
  return { payload: encoded, signatures }
})

const encodeJsonUnencodedPayload = (payload: string): Uint8Array => {
  const invalid = /[\p{Cs}\p{Cn}]/u.exec(payload)?.[0]
  if (invalid !== undefined) {
    failSync(
      "JwsInvalid",
      /\p{Cs}/u.test(invalid)
        ? "JWS Payload must be a well-formed Unicode string"
        : "JWS Payload must not contain unassigned Unicode code points"
    )
  }
  return encoder.encode(payload)
}

const encodeCompactUnencodedPayload = (payload: string): Uint8Array =>
  ascii(payload) ?? failSync("JwsInvalid", "JWS Compact Serialization payload must use only ASCII characters")

const snapshot = (jws: Record<string, unknown>): Flattened => {
  const encodedProtected = jws.protected
  const header = jws.header
  const payload = jws.payload
  const signature = jws.signature
  if (encodedProtected === undefined && header === undefined) {
    failSync("JwsInvalid", "Flattened JWS must have either of the \"protected\" or \"header\" members")
  }
  if (encodedProtected !== undefined && typeof encodedProtected !== "string") {
    failSync("JwsInvalid", "JWS Protected Header incorrect type")
  }
  if (payload === undefined) failSync("JwsInvalid", "JWS Payload missing")
  if (typeof signature !== "string") failSync("JwsInvalid", "JWS Signature missing or incorrect type")
  if (header !== undefined && !isObject(header)) failSync("JwsInvalid", "JWS Unprotected Header incorrect type")
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
): Effect.Effect<VerifyResult & { readonly b64: boolean }, JoseError | E, Crypto.Crypto | R> =>
  Effect.gen(function*() {
    const checked = yield* attempt(() => {
      const algorithms = validateAlgorithms("algorithms", options?.algorithms)
      const protectedHeader = parsedProtected ??
        (jws.protected === undefined
          ? {}
          : parseHeader(jws.protected, "JwsInvalid", "JWS Protected Header is invalid"))
      if (!isDisjoint(protectedHeader, jws.header)) {
        failSync("JwsInvalid", "JWS Protected and JWS Unprotected Header Parameter names must be disjoint")
      }
      const joseHeader: Record<string, unknown> = { ...protectedHeader, ...jws.header }
      const b64 = validateB64(
        protectedHeader,
        validateCrit("JwsInvalid", JWS_RECOGNIZED, options?.crit, protectedHeader, joseHeader)
      )
      const alg = joseHeader.alg
      if (typeof alg !== "string" || !alg) {
        failSync("JwsInvalid", "JWS \"alg\" (Algorithm) Header Parameter missing or invalid")
      }
      if (algorithms && !algorithms.has(alg as string)) {
        failSync("AlgorithmNotAllowed", "\"alg\" (Algorithm) Header Parameter value not allowed")
      }
      const input = jws.payload
      if (b64) {
        if (typeof input !== "string") failSync("JwsInvalid", "JWS Payload must be a string")
      } else if (typeof input !== "string" && !(input instanceof Uint8Array)) {
        failSync("JwsInvalid", "JWS Payload must be a string or an Uint8Array instance")
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
        ? ascii(checked.signingPayload) ?? failSync("JwsInvalid", "The payload is not a valid base64url string")
        : checked.signingPayload
      const data = concat(
        jws.protected !== undefined ? ascii(jws.protected) ?? new Uint8Array() : new Uint8Array(),
        Uint8Array.of(0x2e),
        payloadPart
      )
      const signature = decodeB64u(jws.signature, "signature", "JwsInvalid")
      return { entry, data, signature }
    })
    const { entry } = prepared
    const k = yield* rawKey(yield* prepareKey(entry, resolved, "verify"), entry.key!, "verify")
    if (entry.minRsaBits) yield* attempt(() => checkModulusLength(entry.alg, k))
    const crypto = yield* cryptoService
    const verified = yield* Effect.orElseSucceed(
      crypto.verify(entry.signing, k, prepared.signature, prepared.data),
      () => false
    )
    if (!verified) return yield* fail("SignatureVerificationFailed", "signature verification failed")
    const payload = typeof checked.signingPayload === "string"
      ? yield* attempt(() => decodeB64u(checked.signingPayload as string, "payload", "JwsInvalid"))
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
  jws: string | Uint8Array,
  key: Key | KeyResolver<E, R>,
  options?: VerifyOptions
): Effect.Effect<VerifyResult & { readonly b64: boolean }, JoseError | E, Crypto.Crypto | R> =>
  Effect.suspend(() => {
    const input = jws instanceof Uint8Array ? new TextDecoder().decode(jws) : jws
    if (typeof input !== "string") return fail("JwsInvalid", "Compact JWS must be a string or Uint8Array")
    const parts = input.split(".")
    if (parts.length !== 3) return fail("JwsInvalid", "Invalid Compact JWS")
    return verifySignature(
      { protected: parts[0], payload: parts[1], signature: parts[2] },
      options,
      key,
      encodeCompactUnencodedPayload
    )
  })

/**
 * Verifies a JWS in compact serialization.
 *
 * **Details**
 *
 * `key` may be a key or a {@link KeyResolver}. The result contains the
 * decoded payload bytes and the protected header.
 *
 * @stability unstable
 * @category verification
 * @since 4.0.0
 */
export const verifyCompact = <E = never, R = never>(
  jws: string | Uint8Array,
  key: Key | KeyResolver<E, R>,
  options?: VerifyOptions
): Effect.Effect<VerifyResult, JoseError | E, Crypto.Crypto | R> =>
  Effect.map(verifyCompactInternal(jws, key, options), ({ b64: _, ...result }) => result)

/**
 * Verifies a JWS in flattened JSON serialization.
 *
 * @stability unstable
 * @category verification
 * @since 4.0.0
 */
export const verifyFlattened = <E = never, R = never>(
  jws: Flattened,
  key: Key | KeyResolver<E, R>,
  options?: VerifyOptions
): Effect.Effect<VerifyResult, JoseError | E, Crypto.Crypto | R> =>
  Effect.suspend(() => {
    if (!isObject(jws)) return fail("JwsInvalid", "Flattened JWS must be an object")
    return Effect.flatMap(
      attempt(() => snapshot(jws)),
      (snap) =>
        Effect.map(
          verifySignature(snap, options, key, encodeJsonUnencodedPayload),
          ({ b64: _, ...result }) => result
        )
    )
  })

/**
 * Verifies a JWS in general JSON serialization, succeeding with the first
 * signature that verifies.
 *
 * @stability unstable
 * @category verification
 * @since 4.0.0
 */
export const verifyGeneral = <E = never, R = never>(
  jws: General,
  key: Key | KeyResolver<E, R>,
  options?: VerifyOptions
): Effect.Effect<VerifyResult, JoseError | E, Crypto.Crypto | R> =>
  Effect.gen(function*() {
    if (!isObject(jws)) return yield* fail("JwsInvalid", "General JWS must be an object")
    const { signatures, payload } = jws as unknown as Record<string, unknown>
    if (!Array.isArray(signatures) || !signatures.every(isObject)) {
      return yield* fail("JwsInvalid", "JWS Signatures missing or incorrect type")
    }
    if (payload === undefined) return yield* fail("SignatureVerificationFailed", "signature verification failed")
    const candidates: Array<readonly [Flattened, Record<string, unknown>, number]> = []
    for (const signature of signatures) {
      try {
        const snap = snapshot({ ...signature, payload })
        const protectedHeader = snap.protected === undefined
          ? {}
          : parseHeader(snap.protected, "JwsInvalid", "JWS Protected Header is invalid")
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
      if (modes === 3) return yield* fail("JwsInvalid", "inconsistent use of JWS Unencoded Payload (RFC7797)")
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
    return yield* fail("SignatureVerificationFailed", "signature verification failed")
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
export const decodeProtectedHeader = (token: string): Effect.Effect<Header, JoseError> =>
  attempt(() => {
    if (typeof token !== "string") return failSync("InvalidArgument", "Token must be a string")
    const encoded = token.split(".")[0]
    return parseHeader(encoded, "InvalidArgument", "Invalid Token or Protected Header formatting") as Header
  })
