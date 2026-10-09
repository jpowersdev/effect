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
