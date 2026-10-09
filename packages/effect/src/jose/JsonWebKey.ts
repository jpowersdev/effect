/**
 * Imports, exports, generates, and fingerprints keys for JOSE algorithms
 * (RFC 7517, RFC 7638).
 *
 * Keys are represented as `Crypto.Key` handles from the platform `Crypto`
 * service. Symmetric keys for HMAC and AES-CBC-HMAC content encryption may
 * also be raw `Uint8Array` secrets.
 *
 * @stability unstable
 * @since 4.0.0
 */
import * as Crypto from "../Crypto.ts"
import * as Effect from "../Effect.ts"
import * as Schema from "../Schema.ts"
import { ENC, JWE, JWS } from "./internal/algorithms.ts"
import { jwkToKey, type KeyEntry, normalizeJwk } from "./internal/key.ts"
import {
  attempt,
  b64u,
  b64uDecode,
  encoder,
  fail,
  failSync,
  isCryptoKey,
  isObject,
  mapCryptoError
} from "./internal/shared.ts"
import type { JoseError } from "./JoseError.ts"

/**
 * Structural JSON Web Key data.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Jwk = Crypto.JwkData

const optionalString = Schema.optionalKey(Schema.String)

/**
 * Schema for JSON Web Keys.
 *
 * **Details**
 *
 * Validates the registered JWK parameters from RFC 7517 and RFC 7518. The
 * decoded value drops unregistered parameters.
 *
 * @stability unstable
 * @category schemas
 * @since 4.0.0
 */
export const Jwk = Schema.Struct({
  kty: Schema.String,
  use: optionalString,
  key_ops: Schema.optionalKey(Schema.Array(Schema.String)),
  alg: optionalString,
  kid: optionalString,
  ext: Schema.optionalKey(Schema.Boolean),
  x5u: optionalString,
  x5c: Schema.optionalKey(Schema.Array(Schema.String)),
  x5t: optionalString,
  "x5t#S256": optionalString,
  crv: optionalString,
  x: optionalString,
  y: optionalString,
  d: optionalString,
  n: optionalString,
  e: optionalString,
  p: optionalString,
  q: optionalString,
  dp: optionalString,
  dq: optionalString,
  qi: optionalString,
  k: optionalString
})

/**
 * A key or raw secret produced by import and generation functions.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Key = Crypto.Key | Uint8Array

const ecdhCurve = (crv: string | undefined): Crypto.KeyAlgorithm =>
  crv === "X25519"
    ? { name: "X25519" }
    : crv === undefined || crv === "P-256" || crv === "P-384" || crv === "P-521"
    ? { name: "ECDH", namedCurve: (crv ?? "P-256") as Crypto.NamedCurve }
    : failSync("NotSupported", "Invalid or unsupported crv option provided")

const entryFor = (alg: unknown): KeyEntry => {
  if (typeof alg !== "string") return failSync("InvalidArgument", "\"alg\" argument is required")
  const entry: KeyEntry | undefined = JWS[alg] ?? JWE[alg] ?? ENC[alg]
  if (entry === undefined || alg === "dir") {
    return failSync("NotSupported", "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value")
  }
  return entry
}

/**
 * Imports a JSON Web Key for use with `alg`.
 *
 * **Details**
 *
 * `alg` defaults to the JWK's `alg` parameter. Symmetric `oct` keys are
 * returned as raw secret bytes; other keys are imported as `Crypto.Key`
 * handles. Private keys are not extractable unless `extractable` is set or
 * the JWK sets `ext: true`.
 *
 * @stability unstable
 * @category importing
 * @since 4.0.0
 */
export const importJwk = (
  jwk: Jwk,
  alg?: string,
  options?: { readonly extractable?: boolean | undefined }
): Effect.Effect<Key, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (!isObject(jwk)) return yield* fail("InvalidArgument", "JWK must be an object")
    const normalized = yield* attempt(() => normalizeJwk(jwk))
    const algorithm = alg ?? normalized.alg
    switch (normalized.kty) {
      case "oct": {
        if (typeof normalized.k !== "string" || !normalized.k) {
          return yield* fail("InvalidArgument", "missing \"k\" (Key Value) Parameter value")
        }
        const bytes = b64uDecode(normalized.k)
        if (bytes === undefined) return yield* fail("JwkInvalid", "Failed to base64url decode the \"k\" Parameter")
        return bytes
      }
      case "RSA":
        if ("oth" in normalized && normalized.oth !== undefined) {
          return yield* fail("NotSupported", "RSA JWK \"oth\" (Other Primes Info) Parameter value is not supported")
        }
        break
      case "EC":
      case "OKP":
        break
      default:
        return yield* fail("NotSupported", "Unsupported \"kty\" (Key Type) Parameter value")
    }
    const entry = yield* attempt(() => entryFor(algorithm))
    return yield* jwkToKey(entry, normalized as Jwk, options?.extractable)
  })

const pemToDer = (pem: string, label: string): Uint8Array => {
  const match = new RegExp(`^-----BEGIN ${label}-----\\s*([A-Za-z0-9+/=\\s]+?)\\s*-----END ${label}-----\\s*$`).exec(
    pem.trim()
  )
  if (match === null) return failSync("InvalidArgument", `"pem" must be a PEM-encoded ${label}`)
  const base64 = match[1].replace(/\s+/g, "")
  const url = base64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_")
  return b64uDecode(url) ?? failSync("InvalidArgument", `"pem" must be a PEM-encoded ${label}`)
}

const derToPem = (der: Uint8Array, label: string): string => {
  const base64 = b64u(der).replace(/-/g, "+").replace(/_/g, "/")
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4)
  const lines = padded.match(/.{1,64}/g) ?? []
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`
}

const hasBytes = (haystack: Uint8Array, needle: ReadonlyArray<number>): boolean => {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    return true
  }
  return false
}

const curveOids: ReadonlyArray<readonly [string, ReadonlyArray<number>]> = [
  ["P-256", [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]],
  ["P-384", [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]],
  ["P-521", [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]],
  ["X25519", [0x06, 0x03, 0x2b, 0x65, 0x6e]]
]

const algorithmForDer = (entry: KeyEntry, der: Uint8Array): Crypto.KeyAlgorithm => {
  if (entry.key !== undefined) return entry.key
  const crv = curveOids.find(([, oid]) => hasBytes(der, oid))?.[0]
  if (crv === undefined) return failSync("NotSupported", "Invalid or unsupported key format")
  return entry.resolve!({ kty: crv === "X25519" ? "OKP" : "EC", crv })
}

const importDer = (format: "spki" | "pkcs8", label: string) =>
(
  pem: string,
  alg: string,
  options?: { readonly extractable?: boolean | undefined }
): Effect.Effect<Crypto.Key, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (typeof pem !== "string") return yield* fail("InvalidArgument", `"${format}" must be a string`)
    const { entry, der, algorithm } = yield* attempt(() => {
      const entry = entryFor(alg)
      if (entry.secret) failSync("InvalidArgument", `${format} keys cannot be used with ${alg}`)
      const der = pemToDer(pem, label)
      return { entry, der, algorithm: algorithmForDer(entry, der) }
    })
    const crypto = yield* Crypto.Crypto
    return yield* mapCryptoError(
      crypto.importKey(format, der, algorithm, {
        extractable: options?.extractable ?? format === "spki",
        usages: entry.usages[format === "spki" ? 0 : 1]
      }),
      "InvalidArgument",
      "Invalid or unsupported key format"
    )
  })

/**
 * Imports a PEM-encoded SPKI public key for use with `alg`.
 *
 * @stability unstable
 * @category importing
 * @since 4.0.0
 */
export const importSpki: (
  pem: string,
  alg: string,
  options?: { readonly extractable?: boolean | undefined }
) => Effect.Effect<Crypto.Key, JoseError, Crypto.Crypto> = importDer("spki", "PUBLIC KEY")

/**
 * Imports a PEM-encoded PKCS #8 private key for use with `alg`.
 *
 * @stability unstable
 * @category importing
 * @since 4.0.0
 */
export const importPkcs8: (
  pem: string,
  alg: string,
  options?: { readonly extractable?: boolean | undefined }
) => Effect.Effect<Crypto.Key, JoseError, Crypto.Crypto> = importDer("pkcs8", "PRIVATE KEY")

/**
 * Exports a key or raw secret as a JSON Web Key.
 *
 * @stability unstable
 * @category exporting
 * @since 4.0.0
 */
export const exportJwk = (key: Key): Effect.Effect<Jwk, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (key instanceof Uint8Array) return { kty: "oct", k: b64u(key) }
    if (!isCryptoKey(key)) return yield* fail("InvalidArgument", "Key must be a Crypto.Key or Uint8Array")
    if (!key.extractable) return yield* fail("InvalidArgument", "non-extractable Key cannot be exported as a JWK")
    const crypto = yield* Crypto.Crypto
    const { ext: _ext, key_ops: _ops, alg: _alg, use: _use, ...jwk } = yield* mapCryptoError(
      crypto.exportKey("jwk", key)
    )
    return jwk as Jwk
  })

const exportDer =
  (format: "spki" | "pkcs8", label: string, type: Crypto.Key["type"]) =>
  (key: Crypto.Key): Effect.Effect<string, JoseError, Crypto.Crypto> =>
    Effect.gen(function*() {
      if (!isCryptoKey(key)) return yield* fail("InvalidArgument", "Key must be a Crypto.Key")
      if (!key.extractable) return yield* fail("InvalidArgument", "Key must be extractable")
      if (key.type !== type) return yield* fail("InvalidArgument", `key is not a ${type} key`)
      const crypto = yield* Crypto.Crypto
      return derToPem(yield* mapCryptoError(crypto.exportKey(format, key)), label)
    })

/**
 * Exports an extractable public key as a PEM-encoded SPKI string.
 *
 * @stability unstable
 * @category exporting
 * @since 4.0.0
 */
export const exportSpki: (key: Crypto.Key) => Effect.Effect<string, JoseError, Crypto.Crypto> = exportDer(
  "spki",
  "PUBLIC KEY",
  "public"
)

/**
 * Exports an extractable private key as a PEM-encoded PKCS #8 string.
 *
 * @stability unstable
 * @category exporting
 * @since 4.0.0
 */
export const exportPkcs8: (key: Crypto.Key) => Effect.Effect<string, JoseError, Crypto.Crypto> = exportDer(
  "pkcs8",
  "PRIVATE KEY",
  "private"
)

/**
 * Options for asymmetric key pair generation.
 *
 * **Details**
 *
 * `crv` selects the ECDH-ES curve (`P-256` by default, or `P-384`, `P-521`,
 * `X25519`). `modulusLength` sets the RSA modulus size (2048 by default).
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface GenerateKeyPairOptions {
  readonly extractable?: boolean | undefined
  readonly crv?: string | undefined
  readonly modulusLength?: number | undefined
}

/**
 * Generates a key pair for an asymmetric JWS or JWE algorithm.
 *
 * **Gotchas**
 *
 * Private keys are not extractable unless `extractable` is set.
 *
 * @stability unstable
 * @category generating
 * @since 4.0.0
 */
export const generateKeyPair = (
  alg: string,
  options?: GenerateKeyPairOptions
): Effect.Effect<Crypto.KeyPair, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    const { algorithm, usages } = yield* attempt(() => {
      const entry = entryFor(alg)
      if (entry.secret) failSync("NotSupported", "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value")
      const modulusLength = options?.modulusLength ?? 2048
      if (entry.key !== undefined && "hash" in entry.key && entry.key.name !== "HMAC") {
        if (!Number.isSafeInteger(modulusLength) || modulusLength < 2048) {
          failSync(
            "NotSupported",
            "Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used"
          )
        }
      }
      const algorithm: Crypto.KeyAlgorithm = entry.key === undefined
        ? ecdhCurve(options?.crv)
        : entry.key.name === "RSASSA-PKCS1-v1_5" || entry.key.name === "RSA-PSS" || entry.key.name === "RSA-OAEP"
        ? { ...entry.key, modulusLength }
        : entry.key
      return { algorithm, usages: [...entry.usages[0], ...entry.usages[1]] }
    })
    const crypto = yield* Crypto.Crypto
    const generated = yield* mapCryptoError(
      crypto.generateKey(algorithm, { extractable: options?.extractable ?? false, usages })
    )
    return generated as Crypto.KeyPair
  })

/**
 * Generates a secret key for a symmetric JWS or JWE algorithm.
 *
 * **Details**
 *
 * AES-CBC-HMAC content encryption secrets are returned as raw bytes; other
 * secrets are `Crypto.Key` handles.
 *
 * @stability unstable
 * @category generating
 * @since 4.0.0
 */
export const generateSecret = (
  alg: string,
  options?: { readonly extractable?: boolean | undefined }
): Effect.Effect<Key, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    const crypto = yield* Crypto.Crypto
    const enc = ENC[alg]
    if (enc !== undefined && enc.cbc) return yield* mapCryptoError(crypto.randomBytes(enc.cekBits >> 3))
    const entry = yield* attempt(() => entryFor(alg))
    if (!entry.secret || entry.key === undefined || entry.key.name === "PBKDF2") {
      return yield* fail("NotSupported", "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value")
    }
    const algorithm: Crypto.KeyAlgorithm = entry.key.name === "HMAC"
      ? { ...entry.key, length: Number.parseInt(entry.key.hash.slice(-3), 10) }
      : entry.key
    const usages: ReadonlyArray<Crypto.KeyUsage> = entry.key.name === "HMAC"
      ? ["sign", "verify"]
      : entry.key.name === "AES-KW"
      ? ["wrapKey", "unwrapKey"]
      : ["encrypt", "decrypt"]
    return (yield* mapCryptoError(
      crypto.generateKey(algorithm, { extractable: options?.extractable ?? false, usages })
    )) as Crypto.Key
  })

const required = (jwk: Record<string, unknown>, name: string, description: string): string => {
  const value = jwk[name]
  if (typeof value !== "string" || !value) return failSync("JwkInvalid", `${description} missing or invalid`)
  return value
}

/**
 * Digest algorithms for JWK thumbprints.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type ThumbprintDigest = "sha256" | "sha384" | "sha512"

/**
 * Computes the RFC 7638 thumbprint of a key as a base64url string.
 *
 * **Details**
 *
 * Only the required members for the key type are hashed, so public and
 * private keys of the same pair have the same thumbprint.
 *
 * @stability unstable
 * @category thumbprints
 * @since 4.0.0
 */
export const thumbprint = (
  key: Jwk | Key,
  digest: ThumbprintDigest = "sha256"
): Effect.Effect<string, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    const jwk: Record<string, unknown> = isObject(key) ? { ...key } : yield* exportJwk(key as Key)
    if (typeof jwk.kty !== "string") return yield* fail("InvalidArgument", "Key must be a Crypto.Key or JSON Web Key")
    if (digest !== "sha256" && digest !== "sha384" && digest !== "sha512") {
      return yield* fail("InvalidArgument", "digest must one of \"sha256\", \"sha384\", or \"sha512\"")
    }
    const components = yield* attempt((): Record<string, string> => {
      switch (jwk.kty) {
        case "EC":
          return {
            crv: required(jwk, "crv", "\"crv\" (Curve) Parameter"),
            kty: "EC",
            x: required(jwk, "x", "\"x\" (X Coordinate) Parameter"),
            y: required(jwk, "y", "\"y\" (Y Coordinate) Parameter")
          }
        case "OKP":
          return {
            crv: required(jwk, "crv", "\"crv\" (Subtype of Key Pair) Parameter"),
            kty: "OKP",
            x: required(jwk, "x", "\"x\" (Public Key) Parameter")
          }
        case "RSA":
          return {
            e: required(jwk, "e", "\"e\" (Exponent) Parameter"),
            kty: "RSA",
            n: required(jwk, "n", "\"n\" (Modulus) Parameter")
          }
        case "oct":
          if (typeof jwk.k !== "string") return failSync("JwkInvalid", "\"k\" (Key Value) Parameter missing or invalid")
          return { k: jwk.k, kty: "oct" }
        default:
          return failSync("NotSupported", "\"kty\" (Key Type) Parameter missing or unsupported")
      }
    })
    const crypto = yield* Crypto.Crypto
    const hash = yield* mapCryptoError(
      crypto.digest(`SHA-${digest.slice(-3)}` as Crypto.DigestAlgorithm, encoder.encode(JSON.stringify(components)))
    )
    return b64u(hash)
  })

/**
 * Computes the RFC 9278 JWK thumbprint URI of a key.
 *
 * @stability unstable
 * @category thumbprints
 * @since 4.0.0
 */
export const thumbprintUri = (
  key: Jwk | Key,
  digest: ThumbprintDigest = "sha256"
): Effect.Effect<string, JoseError, Crypto.Crypto> =>
  Effect.map(
    thumbprint(key, digest),
    (value) => `urn:ietf:params:oauth:jwk-thumbprint:sha-${digest.slice(-3)}:${value}`
  )
