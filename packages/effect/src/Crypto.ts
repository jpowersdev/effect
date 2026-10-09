/**
 * Defines a platform-independent service for cryptographic operations.
 *
 * Runtime packages provide concrete implementations backed by the host
 * platform's cryptography APIs. This module defines the service interface and a
 * constructor from random-byte and digest primitives. The service provides
 * secure random bytes and numbers, UUIDv4 and UUIDv7 generation, shuffling, and
 * SHA message digests.
 *
 * @stability unstable
 * @since 4.0.0
 */
import * as Context from "./Context.ts"
import * as Effect from "./Effect.ts"
import * as cryptoKeys from "./internal/cryptoKeys.ts"
import * as random from "./internal/random.ts"
import * as Ulid from "./internal/ulid.ts"
import * as Uuid from "./internal/uuid.ts"
import * as PlatformError from "./PlatformError.ts"

const TypeId = "~effect/Crypto"

/**
 * Digest algorithms supported by the platform `Crypto` service.
 *
 * **Gotchas**
 *
 * SHA-1 is included for interoperability with existing protocols. Do not use
 * SHA-1 for new security-sensitive designs.
 *
 * **Example** (Using a digest algorithm)
 *
 * ```ts import.meta.vitest
 * import { Crypto } from "effect"
 *
 * const algorithm: Crypto.DigestAlgorithm = "SHA-256"
 * ```
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type DigestAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"

/**
 * Operations a cryptographic key may be used for.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type KeyUsage =
  | "encrypt"
  | "decrypt"
  | "sign"
  | "verify"
  | "deriveKey"
  | "deriveBits"
  | "wrapKey"
  | "unwrapKey"

/**
 * Binary key encodings accepted by key import, export, and wrapping
 * operations.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type BinaryKeyFormat = "raw" | "pkcs8" | "spki"

/**
 * JSON Web Key data accepted and produced by key import and export.
 *
 * **Details**
 *
 * This is the structural JWK shape understood by platform cryptography. Use
 * `effect/jose` for validated JWK schemas.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface JwkData {
  readonly kty: string
  readonly [parameter: string]: unknown
}

/**
 * Elliptic curves supported by ECDSA and ECDH keys.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type NamedCurve = "P-256" | "P-384" | "P-521"

/**
 * Algorithms used to import or generate keys.
 *
 * **Details**
 *
 * `length` is in bits. For HMAC it defaults to the block size of `hash`; for
 * AES it is required when generating and inferred from the key when importing.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type KeyAlgorithm =
  | { readonly name: "HMAC"; readonly hash: DigestAlgorithm; readonly length?: number | undefined }
  | {
    readonly name: "RSASSA-PKCS1-v1_5" | "RSA-PSS" | "RSA-OAEP"
    readonly hash: DigestAlgorithm
    readonly modulusLength?: number | undefined
    readonly publicExponent?: Uint8Array | undefined
  }
  | { readonly name: "ECDSA" | "ECDH"; readonly namedCurve: NamedCurve }
  | { readonly name: "Ed25519" | "X25519" }
  | { readonly name: "AES-GCM" | "AES-CBC" | "AES-CTR" | "AES-KW"; readonly length?: number | undefined }
  | { readonly name: "HKDF" | "PBKDF2" }

/**
 * Normalized description of the algorithm a key is bound to.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface KeyAlgorithmInfo {
  readonly name: string
  readonly hash?: DigestAlgorithm | undefined
  readonly namedCurve?: string | undefined
  readonly length?: number | undefined
  readonly modulusLength?: number | undefined
}

/**
 * Opaque handle to a key held by a `Crypto` implementation.
 *
 * **Details**
 *
 * Key material is not exposed directly. Use `exportKey` on an extractable key
 * to read its encoded form.
 *
 * **Gotchas**
 *
 * Keys are bound to the `Crypto` implementation that created them. Passing a
 * key to a different implementation fails with `PlatformError`.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface Key {
  readonly type: "secret" | "public" | "private"
  readonly algorithm: KeyAlgorithmInfo
  readonly extractable: boolean
  readonly usages: ReadonlyArray<KeyUsage>
}

/**
 * Public and private keys produced by asymmetric key generation.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface KeyPair {
  readonly publicKey: Key
  readonly privateKey: Key
}

/**
 * Options controlling the capabilities of an imported, generated, or
 * unwrapped key.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface KeyOptions {
  readonly extractable?: boolean | undefined
  readonly usages: ReadonlyArray<KeyUsage>
}

/**
 * Algorithms used to sign and verify data.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type SignAlgorithm =
  | { readonly name: "HMAC" }
  | { readonly name: "RSASSA-PKCS1-v1_5" }
  | { readonly name: "RSA-PSS"; readonly saltLength: number }
  | { readonly name: "ECDSA"; readonly hash: DigestAlgorithm }
  | { readonly name: "Ed25519" }

/**
 * Algorithms used to encrypt and decrypt data.
 *
 * **Details**
 *
 * For AES-GCM, `tagLength` is in bits and defaults to 128. The authentication
 * tag is appended to the ciphertext.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type CipherAlgorithm =
  | {
    readonly name: "AES-GCM"
    readonly iv: Uint8Array
    readonly additionalData?: Uint8Array | undefined
    readonly tagLength?: number | undefined
  }
  | { readonly name: "AES-CBC"; readonly iv: Uint8Array }
  | { readonly name: "AES-CTR"; readonly counter: Uint8Array; readonly length: number }
  | { readonly name: "RSA-OAEP"; readonly label?: Uint8Array | undefined }

/**
 * Algorithms used to derive bits from a base key.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type DeriveAlgorithm =
  | { readonly name: "ECDH" | "X25519"; readonly public: Key }
  | {
    readonly name: "HKDF"
    readonly hash: DigestAlgorithm
    readonly salt: Uint8Array
    readonly info: Uint8Array
  }
  | {
    readonly name: "PBKDF2"
    readonly hash: DigestAlgorithm
    readonly salt: Uint8Array
    readonly iterations: number
  }

/**
 * Algorithms used to wrap and unwrap keys.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type WrapAlgorithm = { readonly name: "AES-KW" } | CipherAlgorithm

/**
 * Key-based cryptographic operations provided by a `Crypto` implementation.
 *
 * **When to use**
 *
 * Use to supply key operations to `make` when implementing a `Crypto` service.
 * Most platforms can use `makeKeyOperations` with their Web Crypto
 * `SubtleCrypto` object.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface KeyOperations {
  /**
   * Imports binary key material.
   */
  importKey(
    format: BinaryKeyFormat,
    keyData: Uint8Array,
    algorithm: KeyAlgorithm,
    options: KeyOptions
  ): Effect.Effect<Key, PlatformError.PlatformError>
  /**
   * Imports a JSON Web Key.
   */
  importKey(
    format: "jwk",
    keyData: JwkData,
    algorithm: KeyAlgorithm,
    options: KeyOptions
  ): Effect.Effect<Key, PlatformError.PlatformError>

  /**
   * Exports an extractable key in a binary encoding.
   */
  exportKey(format: BinaryKeyFormat, key: Key): Effect.Effect<Uint8Array, PlatformError.PlatformError>
  /**
   * Exports an extractable key as a JSON Web Key.
   */
  exportKey(format: "jwk", key: Key): Effect.Effect<JwkData, PlatformError.PlatformError>

  /**
   * Generates a key, or a key pair for asymmetric algorithms.
   */
  generateKey(algorithm: KeyAlgorithm, options: KeyOptions): Effect.Effect<Key | KeyPair, PlatformError.PlatformError>

  /**
   * Computes a signature or MAC over `data`.
   */
  sign(algorithm: SignAlgorithm, key: Key, data: Uint8Array): Effect.Effect<Uint8Array, PlatformError.PlatformError>

  /**
   * Checks a signature or MAC over `data`.
   */
  verify(
    algorithm: SignAlgorithm,
    key: Key,
    signature: Uint8Array,
    data: Uint8Array
  ): Effect.Effect<boolean, PlatformError.PlatformError>

  /**
   * Encrypts `data`.
   */
  encrypt(
    algorithm: CipherAlgorithm,
    key: Key,
    data: Uint8Array
  ): Effect.Effect<Uint8Array, PlatformError.PlatformError>

  /**
   * Decrypts `data`, failing when authentication or padding checks fail.
   */
  decrypt(
    algorithm: CipherAlgorithm,
    key: Key,
    data: Uint8Array
  ): Effect.Effect<Uint8Array, PlatformError.PlatformError>

  /**
   * Derives `length` bits from a base key.
   */
  deriveBits(
    algorithm: DeriveAlgorithm,
    baseKey: Key,
    length: number
  ): Effect.Effect<Uint8Array, PlatformError.PlatformError>

  /**
   * Encrypts an extractable key with a wrapping key.
   */
  wrapKey(
    format: BinaryKeyFormat,
    key: Key,
    wrappingKey: Key,
    algorithm: WrapAlgorithm
  ): Effect.Effect<Uint8Array, PlatformError.PlatformError>

  /**
   * Decrypts a wrapped key and imports it.
   */
  unwrapKey(
    format: BinaryKeyFormat,
    wrappedKey: Uint8Array,
    unwrappingKey: Key,
    algorithm: WrapAlgorithm,
    keyAlgorithm: KeyAlgorithm,
    options: KeyOptions
  ): Effect.Effect<Key, PlatformError.PlatformError>
}

/**
 * Structural subset of the Web Crypto `SubtleCrypto` interface accepted by
 * `makeKeyOperations`.
 *
 * **Details**
 *
 * Declared structurally so the core package does not depend on DOM or Node
 * type libraries. `globalThis.crypto.subtle` satisfies this interface in
 * browsers, Deno, Bun, and Node.js.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface SubtleCryptoLike {
  importKey(format: string, keyData: any, algorithm: any, extractable: boolean, usages: Array<any>): Promise<any>
  exportKey(format: string, key: any): Promise<any>
  generateKey(algorithm: any, extractable: boolean, usages: Array<any>): Promise<any>
  sign(algorithm: any, key: any, data: any): Promise<ArrayBuffer>
  verify(algorithm: any, key: any, signature: any, data: any): Promise<boolean>
  encrypt(algorithm: any, key: any, data: any): Promise<ArrayBuffer>
  decrypt(algorithm: any, key: any, data: any): Promise<ArrayBuffer>
  deriveBits(algorithm: any, baseKey: any, length: number): Promise<ArrayBuffer>
  wrapKey(format: string, key: any, wrappingKey: any, algorithm: any): Promise<ArrayBuffer>
  unwrapKey(
    format: string,
    wrappedKey: any,
    unwrappingKey: any,
    unwrapAlgorithm: any,
    unwrappedKeyAlgorithm: any,
    extractable: boolean,
    usages: Array<any>
  ): Promise<any>
}

/**
 * Creates key operations backed by a Web Crypto `SubtleCrypto` object.
 *
 * **When to use**
 *
 * Use when implementing a `Crypto` service for a runtime that exposes the Web
 * Crypto API, passing the result as the `keys` option of `make`.
 *
 * **Details**
 *
 * Keys returned by these operations wrap native `CryptoKey` values and can only
 * be used with operations created by the same call.
 *
 * **Example** (Creating key operations from Web Crypto)
 *
 * ```ts import.meta.vitest
 * import { Crypto, Effect } from "effect"
 *
 * const crypto = Crypto.make({
 *   randomBytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)),
 *   digest: (_algorithm, data) => Effect.succeed(data),
 *   keys: Crypto.makeKeyOperations(globalThis.crypto.subtle)
 * })
 *
 * const program = Effect.gen(function*() {
 *   const key = yield* crypto.importKey("raw", new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, {
 *     usages: ["sign"]
 *   })
 *   const mac = yield* crypto.sign({ name: "HMAC" }, key, new Uint8Array([1, 2, 3]))
 *   return mac.length
 * })
 *
 * await Effect.runPromise(program) // => 32
 * ```
 *
 * @stability unstable
 * @category constructors
 * @since 4.0.0
 */
export const makeKeyOperations: (subtle: SubtleCryptoLike) => KeyOperations = cryptoKeys.makeKeyOperations

/**
 * Platform-agnostic cryptographic operations.
 *
 * **Details**
 *
 * `Crypto` implementations must use cryptographically secure platform APIs.
 * The random generator helpers are derived by the `make` constructor from
 * the random methods on this service.
 *
 * **Example** (Using cryptographic operations)
 *
 * ```ts import.meta.vitest
 * import { Crypto, Effect, Layer } from "effect"
 *
 * const TestCrypto = Layer.succeed(
 *   Crypto.Crypto,
 *   Crypto.make({
 *     randomBytes: (size) => new Uint8Array(size),
 *     digest: (_algorithm, data) => Effect.succeed(data)
 *   })
 * )
 *
 * const program = Effect.gen(function*() {
 *   const crypto = yield* Crypto.Crypto
 *   const bytes = yield* crypto.randomBytes(16)
 *   const uuidv4 = yield* crypto.randomUUIDv4()
 *   const hash = yield* crypto.digest("SHA-256", bytes)
 *   return [bytes.length, uuidv4.length, hash.length]
 * })
 *
 * await Effect.runPromise(Effect.provide(program, TestCrypto)) // => [16, 36, 16]
 * ```
 *
 * @stability unstable
 * @category services
 * @since 4.0.0
 */
export interface Crypto extends KeyOperations {
  readonly [TypeId]: typeof TypeId

  /**
   * Generates a random integer in the range Number.MIN_SAFE_INTEGER to
   * Number.MAX_SAFE_INTEGER (both inclusive).
   */
  nextIntUnsafe(): number

  /**
   * Generates a random number in the range 0 (inclusive) to 1 (exclusive).
   */
  nextDoubleUnsafe(): number

  /**
   * Generates cryptographically secure random bytes.
   */
  randomBytes(size: number): Effect.Effect<Uint8Array, PlatformError.PlatformError>

  /**
   * Computes a cryptographic digest for the supplied data.
   */
  digest(
    algorithm: DigestAlgorithm,
    data: Uint8Array
  ): Effect.Effect<Uint8Array, PlatformError.PlatformError>

  /**
   * Generates a cryptographically secure random number between 0 (inclusive)
   * and 1 (exclusive).
   */
  readonly random: Effect.Effect<number>

  /**
   * Generates a cryptographically secure random boolean.
   */
  readonly randomBoolean: Effect.Effect<boolean>

  /**
   * Generates a cryptographically secure random integer between
   * `Number.MIN_SAFE_INTEGER` and `Number.MAX_SAFE_INTEGER` (both inclusive).
   */
  readonly randomInt: Effect.Effect<number>

  /**
   * Generates a cryptographically secure random number between `min`
   * (inclusive) and `max` (exclusive).
   */
  randomBetween(min: number, max: number): Effect.Effect<number>

  /**
   * Generates a cryptographically secure random integer between `min` and `max`.
   *
   * **Details**
   *
   * The lower bound is rounded up with `Math.ceil` and the upper bound is
   * rounded down with `Math.floor`. By default the range is inclusive; set
   * `options.halfOpen: true` to exclude the upper bound.
   */
  randomIntBetween(min: number, max: number, options?: {
    readonly halfOpen?: boolean | undefined
  }): Effect.Effect<number>

  /**
   * Uses the cryptographically secure random generator to shuffle the supplied
   * iterable.
   */
  randomShuffle<A>(elements: Iterable<A>): Effect.Effect<Array<A>>

  /**
   * Generates a cryptographically secure UUIDv4.
   *
   * **Details**
   *
   * The default `"hex"` format returns a lowercase, hyphenated UUID string
   * (36 characters), not a bare hexadecimal string. The `"bytes"` format
   * returns the 16 UUID bytes, including the version and variant bits.
   */
  randomUUIDv4(options?: {
    readonly format?: "hex" | undefined
  }): Effect.Effect<string, PlatformError.PlatformError>
  randomUUIDv4<Format extends "hex" | "bytes">(options: {
    readonly format: Format
  }): Effect.Effect<Format extends "bytes" ? Uint8Array : string, PlatformError.PlatformError>
  randomUUIDv4(options?: {
    readonly format?: "hex" | "bytes" | undefined
  }): Effect.Effect<string | Uint8Array, PlatformError.PlatformError>

  /**
   * Generates a cryptographically secure UUIDv7 using the `Clock` timestamp.
   *
   * **Details**
   *
   * The default `"hex"` format returns a lowercase, hyphenated UUID string
   * (36 characters), not a bare hexadecimal string. The `"bytes"` format
   * returns the 16 UUID bytes, including the timestamp, version and variant bits.
   */
  randomUUIDv7(options?: {
    readonly format?: "hex" | undefined
  }): Effect.Effect<string, PlatformError.PlatformError>
  randomUUIDv7<Format extends "hex" | "bytes">(options: {
    readonly format: Format
  }): Effect.Effect<Format extends "bytes" ? Uint8Array : string, PlatformError.PlatformError>
  randomUUIDv7(options?: {
    readonly format?: "hex" | "bytes" | undefined
  }): Effect.Effect<string | Uint8Array, PlatformError.PlatformError>

  /**
   * Generates a cryptographically secure ULID string.
   *
   * **Details**
   *
   * ULIDs contain 26 uppercase Crockford base32 characters. The first 10 encode
   * the `Clock` timestamp in milliseconds; the remaining 16 encode 80 random
   * bits. ULIDs sort by timestamp, with no ordering guarantee within the same
   * millisecond.
   *
   * Timestamp normalization matches UUIDv7: fractions are truncated, values are
   * clamped to the 48-bit range, and `NaN` encodes as zero.
   */
  readonly randomULID: Effect.Effect<string, PlatformError.PlatformError>
}

/**
 * Service tag for platform cryptography.
 *
 * **When to use**
 *
 * Use when you need to provide or retrieve the full platform cryptography
 * service from an effect's context.
 *
 * **Details**
 *
 * Providing this service supplies platform-agnostic cryptographic operations
 * such as hashing, UUID generation, and secure random values.
 *
 * @see {@link make} for constructing a Crypto service from primitive operations
 *
 * @stability unstable
 * @category services
 * @since 4.0.0
 */
export const Crypto: Context.Service<Crypto, Crypto> = Context.Service("effect/Crypto")

/**
 * Creates a `Crypto` service from the primitive implementation, deriving the
 * random generator helpers and UUID generation from those primitives.
 *
 * **When to use**
 *
 * Use to build a Crypto service for a platform integration, test layer, or
 * custom runtime from primitive random-byte and digest operations.
 *
 * **Details**
 *
 * The constructor derives random numbers, booleans, integer ranges, shuffling,
 * and UUID generation from `impl.randomBytes`. Digest operations delegate to
 * `impl.digest`. Key operations delegate to `impl.keys`; when it is omitted,
 * every key operation fails with `PlatformError`.
 *
 * **Gotchas**
 *
 * `impl.randomBytes` must return cryptographically secure bytes of the
 * requested length. UUID formatting mutates the byte array returned for UUID
 * generation, so the implementation should return a fresh array for each call.
 *
 * **Example** (Creating a Crypto service)
 *
 * ```ts import.meta.vitest
 * import { Crypto, Effect } from "effect"
 *
 * const testCrypto = Crypto.make({
 *   randomBytes: (size) => new Uint8Array(size),
 *   digest: (_algorithm, data) => Effect.succeed(data)
 * })
 *
 * await Effect.runPromise(testCrypto.randomBytes(4)) // => new Uint8Array([0, 0, 0, 0])
 * ```
 *
 * @stability unstable
 * @category constructors
 * @since 4.0.0
 */
export const make = (
  impl: {
    readonly randomBytes: (size: number) => Uint8Array
    readonly digest: (
      algorithm: DigestAlgorithm,
      data: Uint8Array
    ) => Effect.Effect<Uint8Array, PlatformError.PlatformError>
    readonly keys?: KeyOperations | undefined
  }
): Crypto => {
  const randomBytesUnsafe = impl.randomBytes

  const randomBytes: Crypto["randomBytes"] = (size) => Effect.map(validateSize("randomBytes", size), randomBytesUnsafe)

  const readUint53 = (bytes: Uint8Array): number =>
    ((bytes[0] & 0x1f) * 2 ** 48) + (bytes[1] * 2 ** 40) + (bytes[2] * 2 ** 32) +
    (bytes[3] * 2 ** 24) + (bytes[4] * 2 ** 16) + (bytes[5] * 2 ** 8) + bytes[6]

  const nextDoubleUnsafe = (): number => readUint53(randomBytesUnsafe(7)) / 2 ** 53

  const nextIntUnsafe = (): number => {
    while (true) {
      const bytes = randomBytesUnsafe(7)
      const value = readUint53(bytes)
      if ((bytes[0] & 0x20) === 0) {
        return value + Number.MIN_SAFE_INTEGER
      }
      if (value < Number.MAX_SAFE_INTEGER) {
        return value + 1
      }
    }
  }

  const keys = impl.keys ?? cryptoKeys.unsupportedKeyOperations

  return Crypto.of({
    [TypeId]: TypeId,
    importKey: keys.importKey,
    exportKey: keys.exportKey,
    generateKey: keys.generateKey,
    sign: keys.sign,
    verify: keys.verify,
    encrypt: keys.encrypt,
    decrypt: keys.decrypt,
    deriveBits: keys.deriveBits,
    wrapKey: keys.wrapKey,
    unwrapKey: keys.unwrapKey,
    randomBytes,
    nextDoubleUnsafe,
    nextIntUnsafe,
    digest: impl.digest,
    random: Effect.sync(() => nextDoubleUnsafe()),
    randomBoolean: Effect.sync(() => nextDoubleUnsafe() > 0.5),
    randomInt: Effect.sync(() => nextIntUnsafe()),
    randomBetween: (min, max) => Effect.sync(() => random.nextBetween(min, max, nextDoubleUnsafe())),
    randomIntBetween(min, max, options) {
      const extra = options?.halfOpen === true ? 0 : 1
      return Effect.sync(() => {
        const minInt = Math.ceil(min)
        const maxInt = Math.floor(max)
        return Math.floor(nextDoubleUnsafe() * (maxInt - minInt + extra)) + minInt
      })
    },
    randomShuffle: (elements) =>
      Effect.sync(() => {
        const buffer = Array.from(elements)
        for (let i = buffer.length - 1; i >= 1; i = i - 1) {
          const index = Math.min(i, Math.floor(nextDoubleUnsafe() * (i + 1)))
          const value = buffer[i]!
          buffer[i] = buffer[index]!
          buffer[index] = value
        }
        return buffer
      }),
    randomUUIDv4: ((options?: { readonly format?: "hex" | "bytes" | undefined }) =>
      Effect.sync(() => {
        const bytes = Uuid.v4Bytes(randomBytesUnsafe(16))
        return options?.format === "bytes" ? bytes : Uuid.stringify(bytes)
      })) as Crypto["randomUUIDv4"],
    randomUUIDv7: ((options?: { readonly format?: "hex" | "bytes" | undefined }) =>
      Effect.clockWith((clock) => {
        const bytes = Uuid.v7Bytes(clock.currentTimeMillisUnsafe(), randomBytesUnsafe(16))
        return Effect.succeed(options?.format === "bytes" ? bytes : Uuid.stringify(bytes))
      })) as Crypto["randomUUIDv7"],
    randomULID: Effect.clockWith((clock) =>
      Effect.succeed(Ulid.ulidString(clock.currentTimeMillisUnsafe(), randomBytesUnsafe(10)))
    )
  })
}

const validateSize = (method: string, size: number): Effect.Effect<number, PlatformError.PlatformError> =>
  Number.isSafeInteger(size) && size >= 0
    ? Effect.succeed(size)
    : Effect.fail(PlatformError.badArgument({
      module: "Crypto",
      method,
      description: "size must be a non-negative safe integer"
    }))
