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
import * as Cache from "../Cache.ts"
import * as Context from "../Context.ts"
import * as Crypto from "../Crypto.ts"
import * as Duration from "../Duration.ts"
import * as Effect from "../Effect.ts"
import * as Equal from "../Equal.ts"
import * as Exit from "../Exit.ts"
import * as Hash from "../Hash.ts"
import * as Layer from "../Layer.ts"
import type * as PlatformError from "../PlatformError.ts"
import * as Schema from "../Schema.ts"
import { ENC, JWE, JWS, type Usage } from "./internal/algorithms.ts"
import {
  attemptWith,
  b64u,
  b64uDecode,
  encoder,
  isCryptoKey,
  isObject,
  mapPlatformError,
  raise
} from "./internal/shared.ts"
import { UnsupportedAlgorithmError } from "./JsonWebAlgorithm.ts"

/**
 * Error raised when a key cannot be used for the requested algorithm or
 * operation: the wrong key type, curve, or size; a public key where a
 * private key is needed; a non-extractable key that must be exported; or a
 * JWK whose `alg`, `use`, or `key_ops` forbid the operation.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class InvalidKeyError extends Schema.TaggedError<InvalidKeyError>("effect/jose/JsonWebKey/InvalidKeyError")(
  "InvalidKeyError",
  { message: Schema.String }
) {}

/**
 * Error raised when key data is malformed: a JWK with missing or invalid
 * members, or PEM text that does not contain a valid key.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class MalformedKeyError
  extends Schema.TaggedError<MalformedKeyError>("effect/jose/JsonWebKey/MalformedKeyError")(
    "MalformedKeyError",
    { message: Schema.String, cause: Schema.optional(Schema.Defect()) }
  )
{}

/**
 * Error raised when a key type, curve, or key parameter is not supported,
 * such as an unknown `kty`, RSA multi-prime keys, or RSA keys smaller than
 * 2048 bits.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class UnsupportedKeyError
  extends Schema.TaggedError<UnsupportedKeyError>("effect/jose/JsonWebKey/UnsupportedKeyError")(
    "UnsupportedKeyError",
    { message: Schema.String }
  )
{}

/**
 * Failures from preparing a key for a JOSE operation.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type KeyError =
  | InvalidKeyError
  | MalformedKeyError
  | UnsupportedKeyError
  | UnsupportedAlgorithmError
  | PlatformError.PlatformError

const attempt = attemptWith<KeyError>()
const invalidKey = (message: string) => new InvalidKeyError({ message })
const malformedKey = (message: string) => new MalformedKeyError({ message })
const unsupportedKey = (message: string) => new UnsupportedKeyError({ message })

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

/** @internal */
export interface KeyEntry {
  readonly alg: string
  readonly kty: ReadonlyArray<string>
  readonly secret: boolean
  readonly key: Crypto.KeyAlgorithm | undefined
  readonly resolve?: (jwk: { readonly kty?: unknown; readonly crv?: unknown }) => Crypto.KeyAlgorithm
  readonly usages: readonly [ReadonlyArray<Crypto.KeyUsage>, ReadonlyArray<Crypto.KeyUsage>]
  readonly ops?: readonly [Crypto.KeyUsage | undefined, Crypto.KeyUsage | undefined]
}

const normalizeJwk = (jwk: Record<string, unknown>): Record<string, unknown> => {
  const normalized: Record<string, unknown> = { ...jwk }
  if (normalized.ext !== undefined && typeof normalized.ext !== "boolean") {
    return raise(invalidKey("\"ext\" (Extractable) Parameter must be a boolean"))
  }
  if (normalized.key_ops !== undefined) {
    const value = normalized.key_ops
    const keyOps = Array.isArray(value) ? [...value] : undefined
    if (!keyOps || keyOps.some((op) => typeof op !== "string") || new Set(keyOps).size !== keyOps.length) {
      return raise(invalidKey("\"key_ops\" (Key Operations) Parameter must be an array of unique strings"))
    }
    normalized.key_ops = keyOps
  }
  return normalized
}

const jwkMatchesOp = (entry: KeyEntry, jwk: Record<string, unknown>, usage: Usage) => {
  if (jwk.use !== undefined) {
    const expected = usage === "sign" || usage === "verify" ? "sig" : "enc"
    if (jwk.use !== expected) {
      raise(invalidKey(`Invalid key for this operation, its "use" must be "${expected}" when present`))
    }
  }
  if (jwk.alg !== undefined && jwk.alg !== entry.alg) {
    raise(invalidKey(`Invalid key for this operation, its "alg" must be "${entry.alg}" when present`))
  }
  if (Array.isArray(jwk.key_ops)) {
    const expected = usage === "encrypt" || usage === "decrypt"
      ? entry.ops?.[usage === "encrypt" ? 0 : 1]
      : usage
    if (expected && !jwk.key_ops.includes(expected)) {
      raise(invalidKey(`Invalid key for this operation, its "key_ops" must include "${expected}" when present`))
    }
  }
}

const describe = (u: unknown): string =>
  u === null || u === undefined
    ? ` Received ${u}`
    : typeof u === "object" && (u as any).constructor?.name
    ? ` Received an instance of ${(u as any).constructor.name}`
    : ` Received type ${typeof u}`

/**
 * Caches keys imported from JSON Web Keys.
 *
 * **Details**
 *
 * `get` returns the key for a JWK, algorithm, and operation, running `load`
 * to import it when it is not cached. Operations that accept a JWK consult
 * the cache provided as {@link KeyCache}.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface KeyCache {
  readonly get: <E, R>(
    jwk: Crypto.JwkData,
    alg: string,
    usage: string,
    load: Effect.Effect<Crypto.Key, E, R>
  ) => Effect.Effect<Crypto.Key, E, R>
}

/**
 * The key cache used when importing JSON Web Keys.
 *
 * **Details**
 *
 * By default nothing is cached: a JWK passed to a sign, verify, encrypt, or
 * decrypt operation is imported on every call. Provide {@link layerKeyCache}
 * once in the application's root layer to cache imported keys. Reading this
 * reference never adds a requirement.
 *
 * **Gotchas**
 *
 * Key sets cache their own imported keys, so the cache matters most when JWKs
 * are passed directly, for example when they are loaded from a database per
 * request.
 *
 * @stability unstable
 * @category services
 * @since 4.0.0
 */
export const KeyCache: Context.Reference<KeyCache> = Context.Reference<KeyCache>("effect/jose/JsonWebKey/KeyCache", {
  defaultValue: () => ({ get: (_jwk, _alg, _usage, load) => load })
})

class CacheKey<E, R> implements Equal.Equal {
  readonly id: string
  readonly load: Effect.Effect<Crypto.Key, E, R>
  constructor(id: string, load: Effect.Effect<Crypto.Key, E, R>) {
    this.id = id
    this.load = load
  }
  [Equal.symbol](that: unknown): boolean {
    return that instanceof CacheKey && that.id === this.id
  }
  [Hash.symbol](): number {
    return Hash.string(this.id)
  }
}

const canonicalJson = (value: unknown): string =>
  Array.isArray(value)
    ? `[${value.map(canonicalJson).join(",")}]`
    : value !== null && typeof value === "object"
    ? `{${
      Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson((value as any)[key])}`).join(",")
    }}`
    : JSON.stringify(value) ?? "null"

/**
 * Options for {@link makeKeyCache} and {@link layerKeyCache}.
 *
 * **Details**
 *
 * `capacity` bounds the number of cached keys; the least recently used are
 * evicted first. `timeToLive` bounds how long a key stays cached (unbounded
 * by default). Failed imports are not cached.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface KeyCacheOptions {
  readonly capacity: number
  readonly timeToLive?: Duration.Input | undefined
}

/**
 * Creates a bounded {@link KeyCache} built on `Cache`.
 *
 * **Details**
 *
 * Entries are keyed by the JWK's members, the algorithm, and the operation,
 * so JWKs parsed afresh from JSON on each request still hit the cache, and a
 * key imported for one operation is never reused for another.
 *
 * @stability unstable
 * @category constructors
 * @since 4.0.0
 */
export const makeKeyCache = (options: KeyCacheOptions): Effect.Effect<KeyCache> =>
  Effect.map(
    Cache.makeWith(
      (key: CacheKey<any, any>) => key.load,
      {
        capacity: options.capacity,
        timeToLive: (exit) => Exit.isFailure(exit) ? Duration.zero : (options.timeToLive ?? Duration.infinity),
        requireServicesAt: "lookup"
      }
    ),
    (cache): KeyCache => ({
      get: (jwk, alg, usage, load) =>
        Cache.get(cache, new CacheKey(`${alg}|${usage}|${canonicalJson(jwk)}`, load)) as Effect.Effect<
          Crypto.Key,
          any,
          any
        >
    })
  )

/**
 * Provides a bounded {@link KeyCache} so JWKs passed to JOSE operations are
 * imported once and reused.
 *
 * **When to use**
 *
 * Use as part of the application's root layer, next to the `Crypto` layer,
 * so every operation in the program shares one cache.
 *
 * **Example** (Providing the key cache at the root of a program)
 *
 * ```ts
 * import { Effect, Layer } from "effect"
 * import { JsonWebKey, JsonWebSignature } from "effect/jose"
 *
 * declare const CryptoLive: Layer.Layer<never>
 * declare const loadKeyFor: (token: string) => Effect.Effect<JsonWebKey.Jwk>
 *
 * // Request handling passes JWKs loaded per request; the cache avoids
 * // re-importing the same key on every request.
 * const authenticate = (token: string) =>
 *   Effect.flatMap(loadKeyFor(token), (jwk) => JsonWebSignature.verifyCompact(token, jwk))
 *
 * // Provide the cache once, where the program is assembled.
 * const AppLive = Layer.mergeAll(
 *   CryptoLive,
 *   JsonWebKey.layerKeyCache({ capacity: 1000, timeToLive: "1 hour" })
 * )
 * ```
 *
 * @stability unstable
 * @category layers
 * @since 4.0.0
 */
export const layerKeyCache = (options: KeyCacheOptions): Layer.Layer<never> =>
  Layer.effect(KeyCache, makeKeyCache(options))

/**
 * Converts any supported key input into a platform key or raw secret bytes
 * suitable for `entry`, enforcing key type, `use`, `alg`, and `key_ops`.
 *
 * @internal
 */
export const prepareKey = (
  entry: KeyEntry,
  key: unknown,
  usage: Usage
): Effect.Effect<Crypto.Key | Uint8Array, KeyError, Crypto.Crypto> =>
  Effect.suspend(() => {
    const isPrivate = usage === "decrypt" || usage === "sign"
    if (entry.secret && key instanceof Uint8Array) return Effect.succeed(key)
    if (isObject(key)) {
      return attempt(() => {
        const jwk = normalizeJwk(key)
        if (typeof jwk.kty !== "string") {
          return raise(invalidKey(`Key for the ${entry.alg} algorithm must be a Key or JSON Web Key.${describe(key)}`))
        }
        const valid = entry.secret
          ? jwk.kty === "oct" && typeof jwk.k === "string"
          : jwk.kty !== "oct" && (isPrivate ? typeof jwk.d === "string" : jwk.d === undefined)
        if (!valid) {
          raise(invalidKey(
            entry.secret
              ? "JSON Web Key for symmetric algorithms must have JWK \"kty\" (Key Type) equal to \"oct\" and the JWK \"k\" (Key Value) present"
              : `JSON Web Key for this operation must be a ${isPrivate ? "private" : "public"} JWK`
          ))
        }
        jwkMatchesOp(entry, jwk, usage)
        return jwk
      }).pipe(Effect.flatMap((jwk): Effect.Effect<Crypto.Key | Uint8Array, KeyError, Crypto.Crypto> => {
        if (jwk.kty === "oct") {
          const bytes = b64uDecode(jwk.k as string)
          return bytes === undefined
            ? Effect.fail(malformedKey("Failed to base64url decode the \"k\" (Key Value) Parameter"))
            : Effect.succeed(bytes)
        }
        const data = { ...jwk, alg: entry.alg } as unknown as Crypto.JwkData
        return Effect.flatMap(
          Effect.service(KeyCache),
          (cache) => cache.get(data, entry.alg, usage, jwkToKey(entry, data))
        )
      }))
    }
    if (!isCryptoKey(key)) {
      return Effect.fail(invalidKey(
        `Key for the ${entry.alg} algorithm must be a Key${
          entry.secret ? ", JSON Web Key, or Uint8Array" : " or JSON Web Key"
        }.${describe(key)}`
      ))
    }
    const expectedType = entry.secret ? "secret" : isPrivate ? "private" : "public"
    if (key.type !== expectedType) {
      return Effect.fail(invalidKey(`Key instances must be of type "${expectedType}" for the ${entry.alg} algorithm`))
    }
    return Effect.succeed(key)
  })

/**
 * Imports a JSON Web Key for `entry`, using its `key_ops` when present.
 *
 * @internal
 */
export const jwkToKey = (
  entry: KeyEntry,
  jwk: Crypto.JwkData,
  extractable?: boolean
): Effect.Effect<Crypto.Key, KeyError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (!entry.kty.includes(jwk.kty)) {
      return yield* Effect.fail(invalidKey(`JWK key type "${jwk.kty}" cannot be used with ${entry.alg}`))
    }
    const algorithm = entry.resolve !== undefined
      ? yield* attempt(() => entry.resolve!({ kty: jwk.kty, crv: jwk.crv }))
      : entry.key
    if (algorithm === undefined) {
      return yield* Effect.fail(unsupportedKey(`JWK cannot be used with ${entry.alg}`))
    }
    const isPrivate = typeof jwk.d === "string"
    const { alg: _alg, use: _use, ...keyData } = jwk as Record<string, unknown>
    const ext = extractable ?? (keyData.ext as boolean | undefined)
    if (ext !== undefined) keyData.ext = ext
    else delete keyData.ext
    const crypto = yield* Crypto.Crypto
    const usages = (jwk.key_ops as ReadonlyArray<Crypto.KeyUsage> | undefined) ?? entry.usages[isPrivate ? 1 : 0]
    return yield* mapPlatformError(
      crypto.importKey("jwk", keyData as Crypto.JwkData, algorithm, { extractable: ext ?? !isPrivate, usages }),
      (cause) => new MalformedKeyError({ message: "Invalid JSON Web Key", cause })
    )
  })

const unusable = (name: string | number, prop = "algorithm.name") =>
  raise(invalidKey(`Key does not support this operation, its ${prop} must be ${name}`))

/** @internal */
export const checkUsage = (key: Crypto.Key, usage: Crypto.KeyUsage | undefined) => {
  if (usage && !key.usages.includes(usage)) {
    raise(invalidKey(`Key does not support this operation, its usages must include ${usage}.`))
  }
}

/** @internal */
export const checkCryptoKey = (key: Crypto.Key, expected: Crypto.KeyAlgorithm, usage: Crypto.KeyUsage | undefined) => {
  const algorithm = key.algorithm
  if (algorithm.name !== expected.name) unusable(expected.name)
  if ("hash" in expected && expected.hash !== undefined && algorithm.hash !== expected.hash) {
    unusable(expected.hash, "algorithm.hash")
  }
  if ("namedCurve" in expected && algorithm.namedCurve !== expected.namedCurve) {
    unusable(expected.namedCurve, "algorithm.namedCurve")
  }
  if ("length" in expected && expected.length !== undefined && algorithm.length !== expected.length) {
    unusable(expected.length, "algorithm.length")
  }
  checkUsage(key, usage)
}

/** @internal */
export const checkModulusLength = (alg: string, key: Crypto.Key) => {
  const { modulusLength } = key.algorithm
  if (typeof modulusLength !== "number" || modulusLength < 2048) {
    raise(invalidKey(`${alg} requires key modulusLength to be 2048 bits or larger`))
  }
}

/**
 * Recognizes a platform failure caused by the runtime not supporting an
 * algorithm or key size (for example, Chromium has no 192-bit AES), so it
 * can be reported as {@link UnsupportedAlgorithmError} rather than as a
 * problem with the key.
 *
 * @internal
 */
export const unsupportedByRuntime = (
  algorithm: Crypto.KeyAlgorithm,
  error: PlatformError.PlatformError,
  bits?: number
): UnsupportedAlgorithmError | undefined => {
  const name = (error.reason as { readonly cause?: { readonly name?: unknown } }).cause?.name
  const aes = algorithm.name.startsWith("AES")
  if (name !== "NotSupportedError" && !(aes && name === "OperationError")) return undefined
  const length = bits ?? ("length" in algorithm ? algorithm.length : undefined)
  return new UnsupportedAlgorithmError({
    message: `${
      aes && length !== undefined ? `${length}-bit ${algorithm.name}` : algorithm.name
    } is not supported by this runtime`
  })
}

/**
 * Imports raw secret bytes for `expected`, or checks that an existing key is
 * bound to `expected` and permits `usage`.
 *
 * @internal
 */
export const rawKey = (
  key: Crypto.Key | Uint8Array,
  expected: Crypto.KeyAlgorithm,
  usage: Crypto.KeyUsage,
  extractable = false
): Effect.Effect<Crypto.Key, KeyError, Crypto.Crypto> =>
  Effect.gen(function*() {
    let k: Crypto.Key
    if (key instanceof Uint8Array) {
      const crypto = yield* Crypto.Crypto
      k = yield* mapPlatformError(
        crypto.importKey("raw", key, expected, { extractable, usages: [usage] }),
        (error) =>
          unsupportedByRuntime(expected, error, key.length * 8) ?? invalidKey("Invalid key material for this algorithm")
      )
    } else {
      k = key
    }
    yield* attempt(() => checkCryptoKey(k, expected, usage))
    return k
  })

const ecdhCurve = (crv: string | undefined): Crypto.KeyAlgorithm =>
  crv === "X25519"
    ? { name: "X25519" }
    : crv === undefined || crv === "P-256" || crv === "P-384" || crv === "P-521"
    ? { name: "ECDH", namedCurve: (crv ?? "P-256") as Crypto.NamedCurve }
    : raise(unsupportedKey(`Unsupported curve "${crv}"`))

const entryFor = (alg: unknown): KeyEntry => {
  if (typeof alg !== "string") {
    return raise(invalidKey("An algorithm is required when the JWK has no \"alg\" parameter"))
  }
  const entry: KeyEntry | undefined = JWS[alg] ?? JWE[alg] ?? ENC[alg]
  if (entry === undefined || alg === "dir") {
    return raise(new UnsupportedAlgorithmError({ algorithm: alg, message: `Unsupported algorithm "${alg}"` }))
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
): Effect.Effect<Key, KeyError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (!isObject(jwk)) return yield* Effect.die(new TypeError("JWK must be an object"))
    const normalized = yield* attempt(() => normalizeJwk(jwk))
    const algorithm = alg ?? normalized.alg
    switch (normalized.kty) {
      case "oct": {
        if (typeof normalized.k !== "string" || !normalized.k) {
          return yield* Effect.fail(malformedKey("missing \"k\" (Key Value) Parameter value"))
        }
        const bytes = b64uDecode(normalized.k)
        if (bytes === undefined) {
          return yield* Effect.fail(malformedKey("Failed to base64url decode the \"k\" Parameter"))
        }
        return bytes
      }
      case "RSA":
        if ("oth" in normalized && normalized.oth !== undefined) {
          return yield* Effect.fail(
            unsupportedKey("RSA JWK \"oth\" (Other Primes Info) Parameter value is not supported")
          )
        }
        break
      case "EC":
      case "OKP":
        break
      default:
        return yield* Effect.fail(unsupportedKey("Unsupported \"kty\" (Key Type) Parameter value"))
    }
    const entry = yield* attempt(() => entryFor(algorithm))
    return yield* jwkToKey(entry, normalized as Jwk, options?.extractable)
  })

const pemToDer = (pem: string, label: string): Uint8Array => {
  const match = new RegExp(`^-----BEGIN ${label}-----\\s*([A-Za-z0-9+/=\\s]+?)\\s*-----END ${label}-----\\s*$`).exec(
    pem.trim()
  )
  if (match === null) return raise(malformedKey(`"pem" must be a PEM-encoded ${label}`))
  const base64 = match[1].replace(/\s+/g, "")
  const url = base64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_")
  return b64uDecode(url) ?? raise(malformedKey(`"pem" must be a PEM-encoded ${label}`))
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
  if (crv === undefined) return raise(unsupportedKey("Unsupported key curve"))
  return entry.resolve!({ kty: crv === "X25519" ? "OKP" : "EC", crv })
}

const importDer = (format: "spki" | "pkcs8", label: string) =>
(
  pem: string,
  alg: string,
  options?: { readonly extractable?: boolean | undefined }
): Effect.Effect<Crypto.Key, KeyError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (typeof pem !== "string") return yield* Effect.die(new TypeError(`"${format}" must be a string`))
    const { entry, der, algorithm } = yield* attempt(() => {
      const entry = entryFor(alg)
      if (entry.secret) raise(invalidKey(`${format} keys cannot be used with ${alg}`))
      const der = pemToDer(pem, label)
      return { entry, der, algorithm: algorithmForDer(entry, der) }
    })
    const crypto = yield* Crypto.Crypto
    return yield* mapPlatformError(
      crypto.importKey(format, der, algorithm, {
        extractable: options?.extractable ?? format === "spki",
        usages: entry.usages[format === "spki" ? 0 : 1]
      }),
      (cause) => new MalformedKeyError({ message: "Invalid or unsupported key format", cause })
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
) => Effect.Effect<Crypto.Key, KeyError, Crypto.Crypto> = importDer("spki", "PUBLIC KEY")

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
) => Effect.Effect<Crypto.Key, KeyError, Crypto.Crypto> = importDer("pkcs8", "PRIVATE KEY")

/**
 * Exports a key or raw secret as a JSON Web Key.
 *
 * @stability unstable
 * @category exporting
 * @since 4.0.0
 */
export const exportJwk = (key: Key): Effect.Effect<Jwk, InvalidKeyError | PlatformError.PlatformError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (key instanceof Uint8Array) return { kty: "oct", k: b64u(key) }
    if (!isCryptoKey(key)) return yield* Effect.die(new TypeError("Key must be a Crypto.Key or Uint8Array"))
    if (!key.extractable) return yield* Effect.fail(invalidKey("non-extractable Key cannot be exported as a JWK"))
    const crypto = yield* Crypto.Crypto
    const { ext: _ext, key_ops: _ops, alg: _alg, use: _use, ...jwk } = yield* crypto.exportKey("jwk", key)
    return jwk as Jwk
  })

const exportDer =
  (format: "spki" | "pkcs8", label: string, type: Crypto.Key["type"]) =>
  (key: Crypto.Key): Effect.Effect<string, InvalidKeyError | PlatformError.PlatformError, Crypto.Crypto> =>
    Effect.gen(function*() {
      if (!isCryptoKey(key)) return yield* Effect.die(new TypeError("Key must be a Crypto.Key"))
      if (!key.extractable) return yield* Effect.fail(invalidKey("Key must be extractable"))
      if (key.type !== type) return yield* Effect.fail(invalidKey(`key is not a ${type} key`))
      const crypto = yield* Crypto.Crypto
      return derToPem(yield* crypto.exportKey(format, key), label)
    })

/**
 * Exports an extractable public key as a PEM-encoded SPKI string.
 *
 * @stability unstable
 * @category exporting
 * @since 4.0.0
 */
export const exportSpki: (
  key: Crypto.Key
) => Effect.Effect<string, InvalidKeyError | PlatformError.PlatformError, Crypto.Crypto> = exportDer(
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
export const exportPkcs8: (
  key: Crypto.Key
) => Effect.Effect<string, InvalidKeyError | PlatformError.PlatformError, Crypto.Crypto> = exportDer(
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
): Effect.Effect<Crypto.KeyPair, KeyError, Crypto.Crypto> =>
  Effect.gen(function*() {
    const { algorithm, usages } = yield* attempt(() => {
      const entry = entryFor(alg)
      if (entry.secret) {
        raise(new UnsupportedAlgorithmError({ algorithm: alg, message: `${alg} uses a secret; use generateSecret` }))
      }
      const modulusLength = options?.modulusLength ?? 2048
      if (entry.key !== undefined && "hash" in entry.key && entry.key.name !== "HMAC") {
        if (!Number.isSafeInteger(modulusLength) || modulusLength < 2048) {
          raise(unsupportedKey("RSA keys smaller than 2048 bits are not supported"))
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
    const generated = yield* crypto.generateKey(algorithm, { extractable: options?.extractable ?? false, usages })
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
): Effect.Effect<Key, KeyError, Crypto.Crypto> =>
  Effect.gen(function*() {
    const crypto = yield* Crypto.Crypto
    const enc = ENC[alg]
    if (enc !== undefined && enc.cbc) return yield* crypto.randomBytes(enc.cekBits >> 3)
    const entry = yield* attemptWith<UnsupportedAlgorithmError | InvalidKeyError>()(() => entryFor(alg))
    if (!entry.secret || entry.key === undefined || entry.key.name === "PBKDF2") {
      return yield* Effect.fail(
        new UnsupportedAlgorithmError({ algorithm: alg, message: `${alg} does not use a secret key` })
      )
    }
    const algorithm: Crypto.KeyAlgorithm = entry.key.name === "HMAC"
      ? { ...entry.key, length: Number.parseInt(entry.key.hash.slice(-3), 10) }
      : entry.key
    const usages: ReadonlyArray<Crypto.KeyUsage> = entry.key.name === "HMAC"
      ? ["sign", "verify"]
      : entry.key.name === "AES-KW"
      ? ["wrapKey", "unwrapKey"]
      : ["encrypt", "decrypt"]
    return (yield* mapPlatformError(
      crypto.generateKey(algorithm, { extractable: options?.extractable ?? false, usages }),
      (error) => unsupportedByRuntime(algorithm, error) ?? error
    )) as Crypto.Key
  })

const required = (jwk: Record<string, unknown>, name: string, description: string): string => {
  const value = jwk[name]
  if (typeof value !== "string" || !value) return raise(malformedKey(`${description} missing or invalid`))
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
): Effect.Effect<string, KeyError, Crypto.Crypto> =>
  Effect.gen(function*() {
    const jwk: Record<string, unknown> = isObject(key) ? { ...key } : yield* exportJwk(key as Key)
    if (typeof jwk.kty !== "string") return yield* Effect.die(new TypeError("Key must be a Crypto.Key or JSON Web Key"))
    if (digest !== "sha256" && digest !== "sha384" && digest !== "sha512") {
      return yield* Effect.die(new TypeError("digest must one of \"sha256\", \"sha384\", or \"sha512\""))
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
          if (typeof jwk.k !== "string") return raise(malformedKey("\"k\" (Key Value) Parameter missing or invalid"))
          return { k: jwk.k, kty: "oct" }
        default:
          return raise(unsupportedKey("\"kty\" (Key Type) Parameter missing or unsupported"))
      }
    })
    const crypto = yield* Crypto.Crypto
    const hash = yield* crypto.digest(
      `SHA-${digest.slice(-3)}` as Crypto.DigestAlgorithm,
      encoder.encode(JSON.stringify(components))
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
): Effect.Effect<string, KeyError, Crypto.Crypto> =>
  Effect.map(
    thumbprint(key, digest),
    (value) => `urn:ietf:params:oauth:jwk-thumbprint:sha-${digest.slice(-3)}:${value}`
  )
