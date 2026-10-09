/**
 * Issues and validates JSON Web Tokens (RFC 7519) following the JWT Best
 * Current Practices (RFC 8725).
 *
 * Tokens are signed with JWS compact serialization or encrypted with JWE
 * compact serialization. Time-based claims are computed and checked with the
 * Effect `Clock`, so `TestClock` controls expiry in tests. Claims can be
 * decoded with a `Schema` to obtain typed payloads.
 *
 * @stability unstable
 * @since 4.0.0
 */
import * as Clock from "../Clock.ts"
import type * as Crypto from "../Crypto.ts"
import * as Duration from "../Duration.ts"
import * as Effect from "../Effect.ts"
import type * as Redacted from "../Redacted.ts"
import * as Schema from "../Schema.ts"
import { attemptWith, isObject, parseHeader, raise, readToken, strictDecoder } from "./internal/shared.ts"
import type * as JsonWebAlgorithm from "./JsonWebAlgorithm.ts"
import * as JsonWebEncryption from "./JsonWebEncryption.ts"
import * as JsonWebSignature from "./JsonWebSignature.ts"

/**
 * Error raised when a token is not a valid JWT: its payload is not a JSON
 * object, it uses an unencoded payload, or it is not in compact
 * serialization.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class MalformedJwtError
  extends Schema.TaggedError<MalformedJwtError>("effect/jose/JsonWebToken/MalformedJwtError")(
    "MalformedJwtError",
    { message: Schema.String }
  )
{}

/**
 * Describes which check failed for a {@link ClaimValidationError}.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type ClaimCheck = "missing" | "invalid" | "check_failed"

/**
 * Error raised when a JWT claim or header fails validation: a required claim
 * is missing, a claim has the wrong type, `iss`, `sub`, `aud`, or `typ` does
 * not match, `nbf` is in the future, `iat` is in the future, or the claims do
 * not match the provided schema.
 *
 * **Details**
 *
 * `claim` names the failing claim, when there is one. `check` describes
 * whether it was missing, had an invalid type, or failed comparison.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class ClaimValidationError
  extends Schema.TaggedError<ClaimValidationError>("effect/jose/JsonWebToken/ClaimValidationError")(
    "ClaimValidationError",
    {
      message: Schema.String,
      claim: Schema.optional(Schema.String),
      check: Schema.Literals(["missing", "invalid", "check_failed"]),
      cause: Schema.optional(Schema.Defect())
    }
  )
{}

/**
 * Error raised when a JWT has expired: its `exp` is not in the future, or its
 * `iat` is older than `maxTokenAge`, after allowing for `clockTolerance`.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class TokenExpiredError
  extends Schema.TaggedError<TokenExpiredError>("effect/jose/JsonWebToken/TokenExpiredError")(
    "TokenExpiredError",
    { message: Schema.String, claim: Schema.Literals(["exp", "iat"]) }
  )
{}

/**
 * Failures from issuing a signed JWT.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type SignError = JsonWebSignature.SignError | MalformedJwtError

/**
 * Failures from validating a JWT's claims.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type ClaimsError = MalformedJwtError | ClaimValidationError | TokenExpiredError

/**
 * Failures from verifying a signed JWT.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type VerifyError = JsonWebSignature.VerifyError | ClaimsError

/**
 * Failures from decrypting an encrypted JWT.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type DecryptError = JsonWebEncryption.DecryptError | ClaimsError

/**
 * Schema for a signed JWT: a JWS in compact serialization with a base64url
 * payload.
 *
 * **Details**
 *
 * The brand records the format, not that the token was verified. Functions
 * that read tokens accept any string, since incoming tokens are untrusted.
 *
 * @stability unstable
 * @category schemas
 * @since 4.0.0
 */
export const Signed = Schema.String.check(
  Schema.isPattern(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+$/, { expected: "a signed JWT" })
).pipe(Schema.brand("~effect/jose/JsonWebToken/Signed"))

/**
 * A signed JWT.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Signed = typeof Signed.Type

/**
 * Schema for an encrypted JWT: a JWE in compact serialization.
 *
 * @stability unstable
 * @category schemas
 * @since 4.0.0
 */
export const Encrypted = Schema.String.check(
  Schema.isPattern(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/, {
    expected: "an encrypted JWT"
  })
).pipe(Schema.brand("~effect/jose/JsonWebToken/Encrypted"))

/**
 * An encrypted JWT.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Encrypted = typeof Encrypted.Type

const malformed = (message: string) => new MalformedJwtError({ message })
const attemptClaims = attemptWith<ClaimsError>()

/**
 * A JWT claims set with the registered claims typed.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface Claims {
  readonly iss?: string | undefined
  readonly sub?: string | undefined
  readonly aud?: string | ReadonlyArray<string> | undefined
  readonly exp?: number | undefined
  readonly nbf?: number | undefined
  readonly iat?: number | undefined
  readonly jti?: string | undefined
  readonly [claim: string]: unknown
}

/**
 * Schema for the registered JWT claims.
 *
 * **Details**
 *
 * Use as a base when building a schema for application claims, for example
 * with `Schema.Struct({ ...JsonWebToken.RegisteredClaims.fields, role: ... })`.
 *
 * @stability unstable
 * @category schemas
 * @since 4.0.0
 */
export const RegisteredClaims = Schema.Struct({
  iss: Schema.optionalKey(Schema.String),
  sub: Schema.optionalKey(Schema.String),
  aud: Schema.optionalKey(Schema.Union([Schema.String, Schema.Array(Schema.String)])),
  exp: Schema.optionalKey(Schema.Finite),
  nbf: Schema.optionalKey(Schema.Finite),
  iat: Schema.optionalKey(Schema.Finite),
  jti: Schema.optionalKey(Schema.String)
})

/**
 * A point in time for a claim: an absolute `Date`, an absolute NumericDate in
 * seconds since the epoch (`number`), or a `Duration` relative to the current
 * `Clock` time.
 *
 * **Gotchas**
 *
 * A plain `number` is an absolute NumericDate. Use a `Duration` such as
 * `"2 hours"` or `Duration.hours(2)` for relative times.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Time = Date | number | Duration.Duration | Exclude<Duration.Input, number>

/**
 * Options for issuing a JWT.
 *
 * **Details**
 *
 * Registered claim options override the same claims in the payload.
 * `issuedAt: true` sets `iat` to the current `Clock` time.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface IssueOptions {
  readonly issuer?: string | undefined
  readonly subject?: string | undefined
  readonly audience?: string | ReadonlyArray<string> | undefined
  readonly jwtId?: string | undefined
  readonly expirationTime?: Time | undefined
  readonly notBefore?: Time | undefined
  readonly issuedAt?: boolean | Time | undefined
}

/**
 * Options for signing a JWT.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface SignOptions extends IssueOptions {
  readonly key: JsonWebSignature.Key
  readonly protectedHeader: JsonWebSignature.Header & { readonly alg: JsonWebAlgorithm.SignatureAlgorithm }
  readonly crit?: Readonly<Record<string, boolean>> | undefined
}

/**
 * Options for validating a JWT claims set.
 *
 * **Details**
 *
 * - `issuer` accepts one or several allowed issuers.
 * - `audience` passes when any expected audience appears in `aud`.
 * - `typ` compares the `typ` header, ignoring an `application/` prefix.
 * - `clockTolerance` allows for clock skew when checking `exp`, `nbf`, and
 *   `iat`.
 * - `maxTokenAge` requires `iat` and rejects older tokens.
 * - `currentDate` overrides the `Clock` time.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface ClaimsOptions {
  readonly issuer?: string | ReadonlyArray<string> | undefined
  readonly subject?: string | undefined
  readonly audience?: string | ReadonlyArray<string> | undefined
  readonly typ?: string | undefined
  readonly requiredClaims?: ReadonlyArray<string> | undefined
  readonly clockTolerance?: Duration.Input | undefined
  readonly maxTokenAge?: Duration.Input | undefined
  readonly currentDate?: Date | undefined
}

/**
 * Options for verifying a signed JWT.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface VerifyOptions extends ClaimsOptions, JsonWebSignature.VerifyOptions {}

/**
 * The result of verifying or decrypting a JWT.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface Result<A> {
  readonly payload: A
  readonly protectedHeader: Record<string, unknown>
}

const epoch = (millis: number) => Math.floor(millis / 1000)

const resolveTime = (label: string, value: Time, now: number): number => {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`Invalid ${label} input`)
    return value
  }
  if (value instanceof Date) {
    const millis = value.getTime()
    if (!Number.isFinite(millis)) throw new TypeError(`Invalid ${label} input`)
    return epoch(millis)
  }
  const duration = Duration.fromInput(value)
  if (duration._tag === "None" || !Duration.isFinite(duration.value)) {
    throw new TypeError(`Invalid ${label} input`)
  }
  return epoch(now) + Math.round(Duration.toSeconds(duration.value))
}

const validateString = (claim: string, value: unknown) => {
  if (typeof value !== "string") throw new TypeError(`"${claim}" claim must be a string`)
}

/** @internal */
export const buildClaims = (claims: Claims, options: IssueOptions, now: number): Uint8Array => {
  if (!isObject(claims)) throw new TypeError("JWT Claims Set MUST be an object")
  const payload: Record<string, unknown> = structuredClone(claims)
  if (options.issuer !== undefined) {
    validateString("iss", options.issuer)
    payload.iss = options.issuer
  }
  if (options.subject !== undefined) {
    validateString("sub", options.subject)
    payload.sub = options.subject
  }
  if (options.audience !== undefined) {
    const aud = options.audience
    if (typeof aud !== "string" && (!Array.isArray(aud) || aud.some((member) => typeof member !== "string"))) {
      throw new TypeError("\"aud\" claim must be a string or an array of strings")
    }
    payload.aud = aud
  }
  if (options.jwtId !== undefined) {
    validateString("jti", options.jwtId)
    payload.jti = options.jwtId
  }
  if (options.notBefore !== undefined) payload.nbf = resolveTime("notBefore", options.notBefore, now)
  if (options.expirationTime !== undefined) {
    payload.exp = resolveTime("expirationTime", options.expirationTime, now)
  }
  if (options.issuedAt !== undefined && options.issuedAt !== false) {
    payload.iat = options.issuedAt === true ? epoch(now) : resolveTime("issuedAt", options.issuedAt, now)
  }
  for (const claim of ["iat", "nbf", "exp"]) {
    const value = payload[claim]
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new TypeError(`"${claim}" claim must be a finite number`)
    }
  }
  return new TextEncoder().encode(JSON.stringify(payload))
}

const rejectUnencoded = () => raise(malformed("JWTs MUST NOT use unencoded payload"))

/**
 * Issues a JWT signed with JWS compact serialization.
 *
 * **Example** (Issuing and verifying a token)
 *
 * ```ts
 * import { Effect } from "effect"
 * import { JsonWebToken } from "effect/jose"
 *
 * const secret = new TextEncoder().encode("a-string-secret-at-least-256-bits-long")
 *
 * const program = Effect.gen(function*() {
 *   const token = yield* JsonWebToken.sign({ role: "admin" }, {
 *     key: secret,
 *     protectedHeader: { alg: "HS256" },
 *     issuer: "urn:example:issuer",
 *     expirationTime: "2 hours",
 *     issuedAt: true
 *   })
 *   const { payload } = yield* JsonWebToken.verify(token, secret, {
 *     algorithms: ["HS256"],
 *     issuer: "urn:example:issuer"
 *   })
 *   return payload.role
 * })
 * ```
 *
 * @stability unstable
 * @category signing
 * @since 4.0.0
 */
export const sign: {
  <S extends Schema.Constraint>(
    claims: S["Type"],
    options: SignOptions & { readonly schema: S }
  ): Effect.Effect<Redacted.Redacted<Signed>, SignError | ClaimValidationError, Crypto.Crypto | S["EncodingServices"]>
  (claims: Claims, options: SignOptions): Effect.Effect<Redacted.Redacted<Signed>, SignError, Crypto.Crypto>
} = (
  claims: unknown,
  options: SignOptions & { readonly schema?: Schema.Constraint }
): Effect.Effect<Redacted.Redacted<Signed>, any, any> =>
  Effect.gen(function*() {
    const encoded = options.schema === undefined ? claims as Claims : yield* encodeWith(options.schema, claims)
    const now = yield* Clock.currentTimeMillis
    const payload = yield* attemptWith<never>()(() => buildClaims(encoded, options, now))
    const token = yield* JsonWebSignature.signCompact(
      payload,
      { key: options.key, protectedHeader: options.protectedHeader, crit: options.crit },
      rejectUnencoded
    )
    return token as unknown as Redacted.Redacted<Signed>
  })

const durationSeconds = (label: string, input: Duration.Input): number => {
  const duration = Duration.fromInput(input)
  if (duration._tag === "None" || !Duration.isFinite(duration.value)) {
    throw new TypeError(`Invalid ${label} input`)
  }
  return Duration.toSeconds(duration.value)
}

const normalizeTyp = (value: string) => {
  const normalized = value.toLowerCase()
  return value.includes("/") ? normalized : `application/${normalized}`
}

const claimError = (message: string, claim: string, check: ClaimCheck, expired = false) =>
  expired
    ? new TokenExpiredError({ message, claim: claim as "exp" | "iat" })
    : new ClaimValidationError({ message, claim, check })

const validateNumericDate = (payload: Record<string, unknown>, claim: string, required = false) => {
  const value = payload[claim]
  if (value === undefined && !required) return undefined
  if (typeof value !== "number") throw claimError(`"${claim}" claim must be a number`, claim, "invalid")
  return value
}

/**
 * Validates a decoded JWT claims set against `options`.
 *
 * @internal
 */
export const validateClaims = (
  protectedHeader: Record<string, unknown>,
  encodedPayload: Uint8Array,
  options: ClaimsOptions,
  nowMillis: number
): Record<string, unknown> => {
  let payload: unknown
  try {
    payload = JSON.parse(strictDecoder.decode(encodedPayload))
  } catch {
    // reported below
  }
  if (!isObject(payload)) return raise(malformed("JWT Claims Set must be a top-level JSON object"))
  const { typ } = options
  if (
    typ !== undefined &&
    (typeof protectedHeader.typ !== "string" || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))
  ) {
    throw claimError("unexpected \"typ\" JWT header value", "typ", "check_failed")
  }
  const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options
  const presence = [...requiredClaims]
  if (maxTokenAge !== undefined) presence.push("iat")
  if (audience !== undefined) presence.push("aud")
  if (subject !== undefined) presence.push("sub")
  if (issuer !== undefined) presence.push("iss")
  for (const claim of new Set(presence.reverse())) {
    if (!Object.hasOwn(payload, claim)) throw claimError(`missing required "${claim}" claim`, claim, "missing")
  }
  if (issuer !== undefined && !(typeof issuer === "string" ? [issuer] : issuer).includes(payload.iss as string)) {
    throw claimError("unexpected \"iss\" claim value", "iss", "check_failed")
  }
  if (subject !== undefined && payload.sub !== subject) {
    throw claimError("unexpected \"sub\" claim value", "sub", "check_failed")
  }
  if (audience !== undefined) {
    const expected = typeof audience === "string" ? [audience] : audience
    const aud = payload.aud
    const present = typeof aud === "string"
      ? expected.includes(aud)
      : Array.isArray(aud)
      ? expected.some((value) => aud.includes(value))
      : false
    if (!present) throw claimError("unexpected \"aud\" claim value", "aud", "check_failed")
  }
  const tolerance = options.clockTolerance === undefined
    ? 0
    : durationSeconds("clockTolerance option", options.clockTolerance)
  const now = epoch(options.currentDate === undefined ? nowMillis : options.currentDate.getTime())
  if (!Number.isFinite(now)) throw new TypeError("Invalid currentDate option input")
  const iat = validateNumericDate(payload, "iat", maxTokenAge !== undefined)
  const nbf = validateNumericDate(payload, "nbf")
  if (nbf !== undefined && nbf > now + tolerance) {
    throw claimError("\"nbf\" claim timestamp check failed", "nbf", "check_failed")
  }
  const exp = validateNumericDate(payload, "exp")
  if (exp !== undefined && exp <= now - tolerance) {
    throw claimError("\"exp\" claim timestamp check failed", "exp", "check_failed", true)
  }
  if (maxTokenAge !== undefined) {
    const age = now - iat!
    const max = durationSeconds("maxTokenAge option", maxTokenAge)
    if (age - tolerance > max) {
      throw claimError("\"iat\" claim timestamp check failed (too far in the past)", "iat", "check_failed", true)
    }
    if (age < -tolerance) {
      throw claimError("\"iat\" claim timestamp check failed (it should be in the past)", "iat", "check_failed")
    }
  }
  return payload
}

const schemaMismatch = (cause: unknown) =>
  new ClaimValidationError({ message: "JWT Claims Set does not match the schema", check: "invalid", cause })

const encodeWith = <S extends Schema.Constraint>(schema: S, claims: unknown) =>
  Effect.flatMap(
    Effect.mapError(Schema.encodeUnknownEffect(schema)(claims, { reportInput: false }), schemaMismatch),
    (encoded): Effect.Effect<Claims, ClaimValidationError> =>
      isObject(encoded)
        ? Effect.succeed(encoded as Claims)
        : Effect.fail(
          new ClaimValidationError({ message: "JWT Claims Set must encode to a JSON object", check: "invalid" })
        )
  )

const decodeWith = <S extends Schema.Constraint>(schema: S) => (payload: Record<string, unknown>) =>
  Effect.mapError(
    Schema.decodeUnknownEffect(schema)(payload, { reportInput: false }),
    (cause) =>
      new ClaimValidationError({
        message: "JWT Claims Set does not match the schema",
        check: "invalid",
        cause
      })
  )

/**
 * Verifies a signed JWT and validates its claims.
 *
 * **Details**
 *
 * When `schema` is provided, the claims set is decoded with it after the
 * registered claims are validated and the result is typed accordingly.
 *
 * **Gotchas**
 *
 * Without `algorithms`, any signature algorithm compatible with the key is
 * accepted. Pin `algorithms` when the key could be valid for several.
 *
 * @stability unstable
 * @category verification
 * @since 4.0.0
 */
export const verify: {
  <S extends Schema.Constraint, E = never, R = never>(
    token: JsonWebSignature.TokenInput,
    key: JsonWebSignature.Key | JsonWebSignature.KeyResolver<E, R>,
    options: VerifyOptions & { readonly schema: S }
  ): Effect.Effect<Result<S["Type"]>, VerifyError | E, Crypto.Crypto | R | S["DecodingServices"]>
  <E = never, R = never>(
    token: JsonWebSignature.TokenInput,
    key: JsonWebSignature.Key | JsonWebSignature.KeyResolver<E, R>,
    options?: VerifyOptions
  ): Effect.Effect<Result<Claims>, VerifyError | E, Crypto.Crypto | R>
} = <E, R>(
  token: JsonWebSignature.TokenInput,
  key: JsonWebSignature.Key | JsonWebSignature.KeyResolver<E, R>,
  options?: VerifyOptions & { readonly schema?: Schema.Constraint }
): Effect.Effect<Result<any>, VerifyError | E, any> =>
  Effect.gen(function*() {
    const verified = yield* JsonWebSignature.verifyCompactInternal(token, key, options)
    if (!verified.b64) return yield* Effect.fail(malformed("JWTs MUST NOT use unencoded payload"))
    const now = yield* Clock.currentTimeMillis
    const protectedHeader = verified.protectedHeader as Record<string, unknown>
    const claims = yield* attemptClaims(() => validateClaims(protectedHeader, verified.payload, options ?? {}, now))
    const payload = options?.schema === undefined ? claims : yield* decodeWith(options.schema)(claims)
    return { payload, protectedHeader }
  })

/**
 * Options for encrypting a JWT.
 *
 * **Details**
 *
 * `replicateIssuerAsHeader`, `replicateSubjectAsHeader`, and
 * `replicateAudienceAsHeader` copy those claims into the protected header as
 * described in RFC 7519 section 5.3.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface EncryptOptions extends IssueOptions, Omit<JsonWebEncryption.EncryptOptions, "protectedHeader"> {
  readonly protectedHeader: JsonWebEncryption.Header & {
    readonly alg: JsonWebAlgorithm.KeyManagementAlgorithm
    readonly enc: JsonWebAlgorithm.ContentEncryptionAlgorithm
  }
  readonly replicateIssuerAsHeader?: boolean | undefined
  readonly replicateSubjectAsHeader?: boolean | undefined
  readonly replicateAudienceAsHeader?: boolean | undefined
}

/**
 * Issues a JWT encrypted with JWE compact serialization.
 *
 * @stability unstable
 * @category encryption
 * @since 4.0.0
 */
export const encrypt: {
  <S extends Schema.Constraint>(
    claims: S["Type"],
    options: EncryptOptions & { readonly schema: S }
  ): Effect.Effect<
    Redacted.Redacted<Encrypted>,
    JsonWebEncryption.EncryptError | ClaimValidationError,
    Crypto.Crypto | S["EncodingServices"]
  >
  (
    claims: Claims,
    options: EncryptOptions
  ): Effect.Effect<Redacted.Redacted<Encrypted>, JsonWebEncryption.EncryptError, Crypto.Crypto>
} = (
  claims: unknown,
  options: EncryptOptions & { readonly schema?: Schema.Constraint }
): Effect.Effect<Redacted.Redacted<Encrypted>, any, any> =>
  Effect.gen(function*() {
    const encoded = options.schema === undefined ? claims as Claims : yield* encodeWith(options.schema, claims)
    const now = yield* Clock.currentTimeMillis
    const bytes = yield* attemptWith<never>()(() => buildClaims(encoded, options, now))
    const payload = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
    const protectedHeader: Record<string, unknown> = { ...options.protectedHeader }
    if (options.replicateIssuerAsHeader) protectedHeader.iss = payload.iss
    if (options.replicateSubjectAsHeader) protectedHeader.sub = payload.sub
    if (options.replicateAudienceAsHeader) protectedHeader.aud = payload.aud
    const token = yield* JsonWebEncryption.encryptCompact(bytes, {
      ...options,
      protectedHeader: protectedHeader as JsonWebEncryption.Header
    })
    return token as unknown as Redacted.Redacted<Encrypted>
  })

/**
 * Options for decrypting a JWT.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface DecryptOptions extends ClaimsOptions, JsonWebEncryption.DecryptOptions {}

/**
 * Decrypts an encrypted JWT and validates its claims.
 *
 * **Details**
 *
 * Claims replicated into the protected header (`iss`, `sub`, `aud`) must
 * match the claims set.
 *
 * @stability unstable
 * @category encryption
 * @since 4.0.0
 */
export const decrypt: {
  <S extends Schema.Constraint, E = never, R = never>(
    token: JsonWebSignature.TokenInput,
    key: JsonWebEncryption.Key | JsonWebEncryption.KeyResolver<E, R>,
    options: DecryptOptions & { readonly schema: S }
  ): Effect.Effect<Result<S["Type"]>, DecryptError | E, Crypto.Crypto | R | S["DecodingServices"]>
  <E = never, R = never>(
    token: JsonWebSignature.TokenInput,
    key: JsonWebEncryption.Key | JsonWebEncryption.KeyResolver<E, R>,
    options?: DecryptOptions
  ): Effect.Effect<Result<Claims>, DecryptError | E, Crypto.Crypto | R>
} = <E, R>(
  token: JsonWebSignature.TokenInput,
  key: JsonWebEncryption.Key | JsonWebEncryption.KeyResolver<E, R>,
  options?: DecryptOptions & { readonly schema?: Schema.Constraint }
): Effect.Effect<Result<any>, DecryptError | E, any> =>
  Effect.gen(function*() {
    const decrypted = yield* JsonWebEncryption.decryptCompact(token, key, options)
    const now = yield* Clock.currentTimeMillis
    const protectedHeader = decrypted.protectedHeader as Record<string, unknown>
    const claims = yield* attemptClaims(() => {
      const payload = validateClaims(protectedHeader, decrypted.plaintext, options ?? {}, now)
      for (const claim of ["iss", "sub", "aud"] as const) {
        if (
          protectedHeader[claim] !== undefined &&
          JSON.stringify(protectedHeader[claim]) !== JSON.stringify(payload[claim])
        ) {
          throw claimError(`replicated "${claim}" claim header parameter mismatch`, claim, "check_failed")
        }
      }
      return payload
    })
    const payload = options?.schema === undefined ? claims : yield* decodeWith(options.schema)(claims)
    return { payload, protectedHeader }
  })

/**
 * Decodes a signed JWT's claims set without verifying its signature.
 *
 * **Gotchas**
 *
 * The returned claims are untrusted. Use {@link verify} before relying on
 * them.
 *
 * @stability unstable
 * @category decoding
 * @since 4.0.0
 */
export const decodeUnverified = (token: JsonWebSignature.TokenInput): Effect.Effect<Claims, MalformedJwtError> =>
  attemptWith<MalformedJwtError>()(() => {
    const input = readToken(token)
    if (input === undefined) throw new TypeError("JWT must be a string, Uint8Array, or Redacted")
    const parts = input.split(".")
    if (parts.length === 5) {
      return raise(malformed("Only JWTs using Compact JWS serialization can be decoded"))
    }
    if (parts.length !== 3) return raise(malformed("Invalid JWT"))
    if (!parts[1]) return raise(malformed("JWTs must contain a payload"))
    return parseHeader(parts[1], malformed, "Invalid JWT Claims Set") as Claims
  })
