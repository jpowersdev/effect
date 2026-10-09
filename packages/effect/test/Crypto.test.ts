import { assert, describe, it } from "@effect/vitest"
import * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import * as TestClock from "effect/testing/TestClock"

const testCrypto = Crypto.make({
  randomBytes: (size) =>
    size === 7 ? Uint8Array.of(0x18, 0, 0, 0, 0, 0, 0) : Uint8Array.from({ length: size }, (_, i) => i),
  digest: (algorithm, data) => Effect.succeed(Uint8Array.of(data.length, algorithm.length))
})

const makeCrypto = (value: bigint) =>
  Crypto.make({
    randomBytes: () =>
      Uint8Array.of(
        Number((value >> 48n) & 0x3fn),
        Number((value >> 40n) & 0xffn),
        Number((value >> 32n) & 0xffn),
        Number((value >> 24n) & 0xffn),
        Number((value >> 16n) & 0xffn),
        Number((value >> 8n) & 0xffn),
        Number(value & 0xffn)
      ),
    digest: (_algorithm, data) => Effect.succeed(data)
  })

describe("Crypto", () => {
  it("uses the module path for its type ID", () => {
    assert.strictEqual(
      (testCrypto as unknown as Record<string, unknown>)["~effect/Crypto"],
      "~effect/Crypto"
    )
  })

  it("supports string literal digest algorithms", () => {
    const algorithm: Crypto.DigestAlgorithm = "SHA-256"
    assert.strictEqual(algorithm, "SHA-256")
  })

  it.effect("randomBytes delegates to the service", () =>
    Effect.gen(function*() {
      const crypto = yield* Crypto.Crypto
      const bytes = yield* crypto.randomBytes(4)
      assert.deepStrictEqual(bytes, Uint8Array.of(0, 1, 2, 3))
    }).pipe(Effect.provideService(Crypto.Crypto, testCrypto)))

  it.effect("random generators delegate to the service", () =>
    Effect.gen(function*() {
      const crypto = yield* Crypto.Crypto
      const random = yield* crypto.random
      const randomInt = yield* crypto.randomInt
      const randomBoolean = yield* crypto.randomBoolean
      const randomBetween = yield* crypto.randomBetween(10, 20)
      const randomBetweenDecimalBounds = yield* crypto.randomBetween(10.5, 20.5)
      const randomIntBetween = yield* crypto.randomIntBetween(1, 6)
      const randomShuffle = yield* crypto.randomShuffle([1, 2, 3])

      assert.strictEqual(random, 0.75)
      assert.strictEqual(randomInt, -2251799813685247)
      assert.strictEqual(randomBoolean, true)
      assert.strictEqual(randomBetween, 17.5)
      assert.strictEqual(randomBetweenDecimalBounds, 18)
      assert.strictEqual(randomIntBetween, 5)
      assert.deepStrictEqual(randomShuffle, [1, 2, 3])
    }).pipe(Effect.provideService(Crypto.Crypto, testCrypto)))

  it.effect("randomBetween excludes the upper bound when the result rounds up", () =>
    Effect.gen(function*() {
      const value = yield* makeCrypto((1n << 53n) - 2n).randomBetween(10, 20)

      assert.isAtLeast(value, 10)
      assert.isBelow(value, 20)
      assert.strictEqual(value, 20 - 2 ** -48)
    }))

  it("maps adjacent random values to adjacent safe integers", () => {
    assert.strictEqual(makeCrypto(0n).nextIntUnsafe(), Number.MIN_SAFE_INTEGER)
    assert.strictEqual(makeCrypto(1n).nextIntUnsafe(), Number.MIN_SAFE_INTEGER + 1)
    assert.strictEqual(makeCrypto(1n << 53n).nextIntUnsafe(), 1)
    assert.strictEqual(makeCrypto((1n << 54n) - 2n).nextIntUnsafe(), Number.MAX_SAFE_INTEGER)
  })

  it.effect("randomIntBetween excludes the upper bound in half-open ranges", () =>
    Effect.gen(function*() {
      const crypto = yield* Crypto.Crypto
      const value = yield* crypto.randomIntBetween(1, 6, { halfOpen: true })
      assert.strictEqual(value, 5)
    }).pipe(Effect.provideService(
      Crypto.Crypto,
      Crypto.make({
        randomBytes: (size) => new Uint8Array(size).fill(0xff),
        digest: (_algorithm, data) => Effect.succeed(data)
      })
    )))

  it.effect("randomUUIDv4 formats UUID bytes from randomBytes", () =>
    Effect.gen(function*() {
      const crypto = yield* Crypto.Crypto
      const uuid = yield* crypto.randomUUIDv4()
      assert.strictEqual(uuid, "00010203-0405-4607-8809-0a0b0c0d0e0f")
      const hex = yield* crypto.randomUUIDv4({ format: "hex" })
      assert.strictEqual(hex, "00010203-0405-4607-8809-0a0b0c0d0e0f")
    }).pipe(Effect.provideService(Crypto.Crypto, testCrypto)))

  it.effect("randomUUIDv7 formats UUID bytes with the Clock timestamp", () =>
    Effect.gen(function*() {
      yield* TestClock.setTime(0x0123456789ab)
      const crypto = yield* Crypto.Crypto
      const uuid = yield* crypto.randomUUIDv7()
      assert.strictEqual(uuid, "01234567-89ab-7607-8809-0a0b0c0d0e0f")
      const hex = yield* crypto.randomUUIDv7({ format: "hex" })
      assert.strictEqual(hex, "01234567-89ab-7607-8809-0a0b0c0d0e0f")
    }).pipe(Effect.provideService(Crypto.Crypto, testCrypto)))

  it.effect("randomUUIDv4 returns 16 bytes with the version and variant bits set", () =>
    Effect.gen(function*() {
      const crypto = yield* Crypto.Crypto
      const bytes = yield* crypto.randomUUIDv4({ format: "bytes" })
      assert.deepStrictEqual(bytes, Uint8Array.of(0, 1, 2, 3, 4, 5, 0x46, 7, 0x88, 9, 10, 11, 12, 13, 14, 15))
    }).pipe(Effect.provideService(Crypto.Crypto, testCrypto)))

  it.effect("randomUUIDv7 returns 16 bytes containing the Clock timestamp, version and variant", () =>
    Effect.gen(function*() {
      yield* TestClock.setTime(0x0123456789ab)
      const crypto = yield* Crypto.Crypto
      const bytes = yield* crypto.randomUUIDv7({ format: "bytes" })
      assert.deepStrictEqual(
        bytes,
        Uint8Array.of(0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x76, 7, 0x88, 9, 10, 11, 12, 13, 14, 15)
      )
    }).pipe(Effect.provideService(Crypto.Crypto, testCrypto)))

  it.effect("randomULID encodes the Clock timestamp and random bytes", () =>
    Effect.gen(function*() {
      yield* TestClock.setTime(0x0123456789ab)
      const crypto = yield* Crypto.Crypto
      const ulid = yield* crypto.randomULID

      assert.strictEqual(ulid, "014D2PF2DB000G40R40M30E209")
    }).pipe(Effect.provideService(Crypto.Crypto, testCrypto)))

  it.effect("randomULID clamps an overflowing Clock timestamp", () =>
    Effect.gen(function*() {
      yield* TestClock.setTime(2 ** 48)
      const crypto = yield* Crypto.Crypto
      const ulid = yield* crypto.randomULID

      assert.strictEqual(ulid, "7ZZZZZZZZZ000G40R40M30E209")
    }).pipe(Effect.provideService(Crypto.Crypto, testCrypto)))

  it.effect("digest delegates to the service", () =>
    Effect.gen(function*() {
      const crypto = yield* Crypto.Crypto
      const digest = yield* crypto.digest("SHA-256", Uint8Array.of(1, 2, 3))
      assert.deepStrictEqual(digest, Uint8Array.of(3, "SHA-256".length))
    }).pipe(Effect.provideService(Crypto.Crypto, testCrypto)))

  it.effect("can access a provided custom Crypto service", () =>
    Effect.gen(function*() {
      const crypto = yield* Crypto.Crypto
      const bytes = yield* crypto.randomBytes(1)
      assert.deepStrictEqual(bytes, Uint8Array.of(0))
    }).pipe(Effect.provideService(Crypto.Crypto, testCrypto)))

  describe("key operations", () => {
    const webCrypto = Crypto.make({
      randomBytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)),
      digest: (_algorithm, data) => Effect.succeed(data),
      keys: Crypto.makeKeyOperations(globalThis.crypto.subtle)
    })

    it.effect("fail with PlatformError when the implementation has no key operations", () =>
      Effect.gen(function*() {
        const error = yield* Effect.flip(
          testCrypto.importKey("raw", new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, { usages: ["sign"] })
        )
        assert.strictEqual(error._tag, "PlatformError")
        assert.include(error.message, "importKey is not supported")
      }))

    it.effect("sign and verify with imported keys", () =>
      Effect.gen(function*() {
        const key = yield* webCrypto.importKey("raw", new Uint8Array(32).fill(7), { name: "HMAC", hash: "SHA-256" }, {
          usages: ["sign", "verify"]
        })
        assert.deepStrictEqual(key.algorithm, { name: "HMAC", hash: "SHA-256", length: 256 })
        assert.strictEqual(key.type, "secret")
        assert.isFalse(key.extractable)
        const data = new Uint8Array([1, 2, 3])
        const mac = yield* webCrypto.sign({ name: "HMAC" }, key, data)
        assert.isTrue(yield* webCrypto.verify({ name: "HMAC" }, key, mac, data))
        assert.isFalse(yield* webCrypto.verify({ name: "HMAC" }, key, mac, new Uint8Array([1, 2, 4])))
      }))

    it.effect("generate, export, encrypt, and decrypt", () =>
      Effect.gen(function*() {
        const key = (yield* webCrypto.generateKey({ name: "AES-GCM", length: 256 }, {
          extractable: true,
          usages: ["encrypt", "decrypt"]
        })) as Crypto.Key
        assert.strictEqual((yield* webCrypto.exportKey("raw", key)).length, 32)
        const iv = new Uint8Array(12)
        const ciphertext = yield* webCrypto.encrypt({ name: "AES-GCM", iv }, key, new Uint8Array([9, 9]))
        assert.deepStrictEqual(yield* webCrypto.decrypt({ name: "AES-GCM", iv }, key, ciphertext), new Uint8Array([9, 9]))
        const tampered = ciphertext.slice()
        tampered[0] ^= 1
        const error = yield* Effect.flip(webCrypto.decrypt({ name: "AES-GCM", iv }, key, tampered))
        assert.strictEqual(error._tag, "PlatformError")
      }))

    it.effect("derive bits with ECDH key pairs", () =>
      Effect.gen(function*() {
        const algorithm = { name: "ECDH", namedCurve: "P-256" } as const
        const a = (yield* webCrypto.generateKey(algorithm, { usages: ["deriveBits"] })) as Crypto.KeyPair
        const b = (yield* webCrypto.generateKey(algorithm, { usages: ["deriveBits"] })) as Crypto.KeyPair
        const ab = yield* webCrypto.deriveBits({ name: "ECDH", public: b.publicKey }, a.privateKey, 256)
        const ba = yield* webCrypto.deriveBits({ name: "ECDH", public: a.publicKey }, b.privateKey, 256)
        assert.deepStrictEqual(ab, ba)
      }))

    it.effect("reject keys created by another implementation", () =>
      Effect.gen(function*() {
        const other = Crypto.makeKeyOperations(globalThis.crypto.subtle)
        const key = yield* other.importKey("raw", new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, {
          usages: ["sign"]
        })
        const error = yield* Effect.flip(webCrypto.sign({ name: "HMAC" }, key, new Uint8Array()))
        assert.strictEqual(error.reason._tag, "BadArgument")
      }))
  })
})
