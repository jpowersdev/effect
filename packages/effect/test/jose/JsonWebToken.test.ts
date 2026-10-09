import { assert, describe, it } from "@effect/vitest"
import * as Effect from "effect/Effect"
import * as Schema from "effect/Schema"
import * as TestClock from "effect/testing/TestClock"
import { JsonWebKey, JsonWebToken } from "effect/jose"
import { CryptoLive, utf8 } from "./utils.ts"

const secret = utf8("a-string-secret-at-least-256-bits-long")
const NOW = 1_700_000_000_000

describe("JsonWebToken", () => {
  it.effect("issues tokens with times from the Clock and expires them", () =>
    Effect.gen(function*() {
      yield* TestClock.setTime(NOW)
      const token = yield* JsonWebToken.sign({ role: "admin" }, {
        key: secret,
        protectedHeader: { alg: "HS256" },
        issuer: "urn:issuer",
        audience: "urn:audience",
        issuedAt: true,
        expirationTime: "1 hour"
      })
      const claims = yield* JsonWebToken.decodeUnverified(token)
      assert.deepStrictEqual(claims, {
        role: "admin",
        iss: "urn:issuer",
        aud: "urn:audience",
        iat: NOW / 1000,
        exp: NOW / 1000 + 3600
      })
      const options = { algorithms: ["HS256"], issuer: "urn:issuer", audience: "urn:audience" }
      yield* JsonWebToken.verify(token, secret, options)
      yield* TestClock.adjust("1 hour")
      const expired = yield* Effect.flip(JsonWebToken.verify(token, secret, options))
      assert.strictEqual(expired.reason, "Expired")
      assert.strictEqual(expired.claim, "exp")
      yield* JsonWebToken.verify(token, secret, { ...options, clockTolerance: "1 second" })
    }).pipe(Effect.provide([CryptoLive, TestClock.layer()])))

  it.effect("validates registered claims", () =>
    Effect.gen(function*() {
      const token = yield* JsonWebToken.sign({ sub: "u1" }, { key: secret, protectedHeader: { alg: "HS256" } })
      const issuer = yield* Effect.flip(JsonWebToken.verify(token, secret, { issuer: "urn:other" }))
      assert.strictEqual(issuer.reason, "ClaimValidationFailed")
      assert.strictEqual(issuer.claim, "iss")
      assert.strictEqual(issuer.check, "missing")
      const subject = yield* Effect.flip(JsonWebToken.verify(token, secret, { subject: "u2" }))
      assert.strictEqual(subject.check, "check_failed")
      const required = yield* Effect.flip(JsonWebToken.verify(token, secret, { requiredClaims: ["jti"] }))
      assert.strictEqual(required.claim, "jti")
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("decodes claims with a schema", () =>
    Effect.gen(function*() {
      const Claims = Schema.Struct({
        ...JsonWebToken.RegisteredClaims.fields,
        role: Schema.Literals(["admin", "user"])
      })
      const token = yield* JsonWebToken.sign({ role: "user" }, { key: secret, protectedHeader: { alg: "HS256" } })
      const { payload } = yield* JsonWebToken.verify(token, secret, { schema: Claims })
      assert.strictEqual(payload.role, "user")
      const bad = yield* JsonWebToken.sign({ role: "root" }, { key: secret, protectedHeader: { alg: "HS256" } })
      const error = yield* Effect.flip(JsonWebToken.verify(bad, secret, { schema: Claims }))
      assert.strictEqual(error.reason, "ClaimValidationFailed")
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("rejects unencoded payloads", () =>
    Effect.gen(function*() {
      const error = yield* Effect.flip(JsonWebToken.sign({}, {
        key: secret,
        protectedHeader: { alg: "HS256", b64: false, crit: ["b64"] }
      }))
      assert.strictEqual(error.reason, "JwtInvalid")
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("encrypts and decrypts tokens with replicated claims", () =>
    Effect.gen(function*() {
      const { privateKey, publicKey } = yield* JsonWebKey.generateKeyPair("ECDH-ES+A256KW")
      const token = yield* JsonWebToken.encrypt({ role: "admin" }, {
        key: publicKey,
        protectedHeader: { alg: "ECDH-ES+A256KW", enc: "A256GCM" },
        issuer: "urn:issuer",
        replicateIssuerAsHeader: true
      })
      const { payload, protectedHeader } = yield* JsonWebToken.decrypt(token, privateKey, { issuer: "urn:issuer" })
      assert.strictEqual(payload.role, "admin")
      assert.strictEqual(protectedHeader.iss, "urn:issuer")
    }).pipe(Effect.provide(CryptoLive)))
})
