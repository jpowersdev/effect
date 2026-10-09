/**
 * Algorithm identifiers from JSON Web Algorithms (RFC 7518), RFC 8037, and
 * RFC 9864, with schemas for validating them.
 *
 * Only algorithms implementable with the platform `Crypto` service are
 * listed. The `none` algorithm, `ES256K`, and JWE compression are not
 * supported.
 *
 * @stability unstable
 * @since 4.0.0
 */
import * as Schema from "../Schema.ts"

/**
 * JWS signature algorithm identifiers.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type SignatureAlgorithm = typeof signatureAlgorithms[number]

/**
 * All supported JWS signature algorithm identifiers.
 *
 * @stability unstable
 * @category constants
 * @since 4.0.0
 */
export const signatureAlgorithms = [
  "HS256",
  "HS384",
  "HS512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
  "Ed25519"
] as const

/**
 * Schema for JWS signature algorithm identifiers.
 *
 * @stability unstable
 * @category schemas
 * @since 4.0.0
 */
export const SignatureAlgorithm: Schema.Literals<typeof signatureAlgorithms> = Schema.Literals(signatureAlgorithms)

/**
 * JWE key management algorithm identifiers.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type KeyManagementAlgorithm = typeof keyManagementAlgorithms[number]

/**
 * All supported JWE key management algorithm identifiers.
 *
 * @stability unstable
 * @category constants
 * @since 4.0.0
 */
export const keyManagementAlgorithms = [
  "dir",
  "RSA-OAEP",
  "RSA-OAEP-256",
  "RSA-OAEP-384",
  "RSA-OAEP-512",
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW",
  "A128KW",
  "A192KW",
  "A256KW",
  "A128GCMKW",
  "A192GCMKW",
  "A256GCMKW",
  "PBES2-HS256+A128KW",
  "PBES2-HS384+A192KW",
  "PBES2-HS512+A256KW"
] as const

/**
 * Schema for JWE key management algorithm identifiers.
 *
 * @stability unstable
 * @category schemas
 * @since 4.0.0
 */
export const KeyManagementAlgorithm: Schema.Literals<typeof keyManagementAlgorithms> = Schema.Literals(
  keyManagementAlgorithms
)

/**
 * JWE content encryption algorithm identifiers.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type ContentEncryptionAlgorithm = typeof contentEncryptionAlgorithms[number]

/**
 * All supported JWE content encryption algorithm identifiers.
 *
 * @stability unstable
 * @category constants
 * @since 4.0.0
 */
export const contentEncryptionAlgorithms = [
  "A128GCM",
  "A192GCM",
  "A256GCM",
  "A128CBC-HS256",
  "A192CBC-HS384",
  "A256CBC-HS512"
] as const

/**
 * Schema for JWE content encryption algorithm identifiers.
 *
 * @stability unstable
 * @category schemas
 * @since 4.0.0
 */
export const ContentEncryptionAlgorithm: Schema.Literals<typeof contentEncryptionAlgorithms> = Schema.Literals(
  contentEncryptionAlgorithms
)

/**
 * Error raised when an algorithm identifier is not supported, such as `none`,
 * an unknown `alg` or `enc` value, or a key type or curve that no supported
 * algorithm can use.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class UnsupportedAlgorithmError
  extends Schema.TaggedError<UnsupportedAlgorithmError>("effect/jose/JsonWebAlgorithm/UnsupportedAlgorithmError")(
    "UnsupportedAlgorithmError",
    {
      algorithm: Schema.optional(Schema.String),
      message: Schema.String
    }
  )
{}

/**
 * Error raised when a token's algorithm is supported but not in the caller's
 * allow list (`algorithms`, `keyManagementAlgorithms`, or
 * `contentEncryptionAlgorithms`), or is PBES2 without being allowed
 * explicitly.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class AlgorithmNotAllowedError
  extends Schema.TaggedError<AlgorithmNotAllowedError>("effect/jose/JsonWebAlgorithm/AlgorithmNotAllowedError")(
    "AlgorithmNotAllowedError",
    {
      parameter: Schema.Literals(["alg", "enc"]),
      algorithm: Schema.String,
      message: Schema.String
    }
  )
{}

/**
 * Any supported JOSE algorithm identifier.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Algorithm = SignatureAlgorithm | KeyManagementAlgorithm | ContentEncryptionAlgorithm
