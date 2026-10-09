/**
 * The error type shared by the `effect/jose` modules.
 *
 * Every failure produced while signing, verifying, encrypting, decrypting,
 * importing keys, or validating JWT claims is a {@link JoseError} carrying a
 * {@link JoseErrorReason}. Reasons correspond to the error classes of the
 * JOSE specifications, and {@link JoseError.code} exposes the conventional
 * `ERR_*` code used by other JOSE implementations.
 *
 * @stability unstable
 * @since 4.0.0
 */
import * as Data from "../Data.ts"
import { hasProperty } from "../Predicate.ts"

const TypeId = "~effect/jose/JoseError" as const

/**
 * Classifies why a JOSE operation failed.
 *
 * **Details**
 *
 * - `JwsInvalid`, `JweInvalid`, `JwtInvalid`, `JwkInvalid`, `JwksInvalid`:
 *   the input is structurally invalid for that format.
 * - `AlgorithmNotAllowed`: the algorithm is valid but not in the caller's
 *   allow list.
 * - `NotSupported`: the algorithm, key type, or extension is not supported.
 * - `SignatureVerificationFailed`: the signature does not match.
 * - `DecryptionFailed`: authenticated decryption failed.
 * - `ClaimValidationFailed`, `Expired`: a JWT claim check failed.
 * - `NoMatchingKey`, `MultipleMatchingKeys`: key set selection failed.
 * - `InvalidKey`: the key cannot be used with the requested algorithm or
 *   operation.
 * - `InvalidArgument`: an option or argument is invalid.
 * - `CryptoFailure`: the platform `Crypto` service failed unexpectedly.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type JoseErrorReason =
  | "JwsInvalid"
  | "JweInvalid"
  | "JwtInvalid"
  | "JwkInvalid"
  | "JwksInvalid"
  | "AlgorithmNotAllowed"
  | "NotSupported"
  | "SignatureVerificationFailed"
  | "DecryptionFailed"
  | "ClaimValidationFailed"
  | "Expired"
  | "NoMatchingKey"
  | "MultipleMatchingKeys"
  | "InvalidKey"
  | "InvalidArgument"
  | "CryptoFailure"

/**
 * Describes which check failed for a JWT claim validation error.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type ClaimCheck = "missing" | "invalid" | "check_failed"

/**
 * Error raised by JOSE operations.
 *
 * **Details**
 *
 * `claim` and `check` are set for `ClaimValidationFailed` and `Expired`
 * reasons. `cause` holds an underlying platform or schema error when present.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class JoseError extends Data.TaggedError("JoseError")<{
  readonly reason: JoseErrorReason
  readonly message: string
  readonly claim?: string | undefined
  readonly check?: ClaimCheck | undefined
  readonly cause?: unknown
}> {
  /**
   * Marks this value as a JOSE error for runtime guards.
   *
   * @since 4.0.0
   */
  readonly [TypeId]: typeof TypeId = TypeId

  /**
   * Returns the conventional `ERR_*` code for this error, or `undefined` for
   * argument, key, and platform failures that have no JOSE error code.
   *
   * @since 4.0.0
   */
  get code(): string | undefined {
    return codes[this.reason]
  }
}

const codes: Record<JoseErrorReason, string | undefined> = {
  JwsInvalid: "ERR_JWS_INVALID",
  JweInvalid: "ERR_JWE_INVALID",
  JwtInvalid: "ERR_JWT_INVALID",
  JwkInvalid: "ERR_JWK_INVALID",
  JwksInvalid: "ERR_JWKS_INVALID",
  AlgorithmNotAllowed: "ERR_JOSE_ALG_NOT_ALLOWED",
  NotSupported: "ERR_JOSE_NOT_SUPPORTED",
  SignatureVerificationFailed: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
  DecryptionFailed: "ERR_JWE_DECRYPTION_FAILED",
  ClaimValidationFailed: "ERR_JWT_CLAIM_VALIDATION_FAILED",
  Expired: "ERR_JWT_EXPIRED",
  NoMatchingKey: "ERR_JWKS_NO_MATCHING_KEY",
  MultipleMatchingKeys: "ERR_JWKS_MULTIPLE_MATCHING_KEYS",
  InvalidKey: undefined,
  InvalidArgument: undefined,
  CryptoFailure: undefined
}

/**
 * Checks whether a value is a {@link JoseError}.
 *
 * @stability unstable
 * @category guards
 * @since 4.0.0
 */
export const isJoseError = (u: unknown): u is JoseError => hasProperty(u, TypeId)
