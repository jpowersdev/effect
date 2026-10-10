import { assert, describe, it } from "@effect/vitest"
import * as Effect from "effect/Effect"
import { JsonWebKey, JsonWebToken } from "effect/jose"
import * as Schema from "effect/Schema"
import * as TestClock from "effect/testing/TestClock"
import { JoseLive, utf8 } from "./utils.ts"

const secret = utf8("a-string-secret-at-least-256-bits-long")
const NOW = 1_700_000_000_000

describe("JsonWebToken", () => {
  it.effect("issues tokens with times from the Clock and expires them", () =>
    Effect.gen(function*() {
      const jwt = yield* JsonWebToken.JsonWebToken
      yield* TestClock.setTime(NOW)
      const token = yield* jwt.sign({ role: "admin" }, {
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
      const options = { algorithms: ["HS256"], issuer: "urn:issuer", audience: "urn:audience" } as const
      yield* jwt.verify(token, secret, options)
      yield* TestClock.adjust("1 hour")
      const expired = yield* Effect.flip(jwt.verify(token, secret, options))
      assert(expired._tag === "TokenExpiredError")
      assert.strictEqual(expired.claim, "exp")
      yield* jwt.verify(token, secret, { ...options, clockTolerance: "1 second" })
    }).pipe(Effect.provide([JoseLive, TestClock.layer()])))

  it.effect("validates registered claims", () =>
    Effect.gen(function*() {
      const jwt = yield* JsonWebToken.JsonWebToken
      const token = yield* jwt.sign({ sub: "u1" }, {
        key: secret,
        expirationTime: "1 hour",
        protectedHeader: { alg: "HS256" }
      })
      const issuer = yield* Effect.flip(
        jwt.verify(token, secret, { algorithms: ["HS256"], issuer: "urn:other" })
      )
      assert(issuer._tag === "ClaimValidationError")
      assert.strictEqual(issuer.claim, "iss")
      assert.strictEqual(issuer.check, "missing")
      const subject = yield* Effect.flip(jwt.verify(token, secret, { algorithms: ["HS256"], subject: "u2" }))
      assert(subject._tag === "ClaimValidationError")
      assert.strictEqual(subject.check, "check_failed")
      const required = yield* Effect.flip(
        jwt.verify(token, secret, { algorithms: ["HS256"], requiredClaims: ["jti"] })
      )
      assert(required._tag === "ClaimValidationError")
      assert.strictEqual(required.claim, "jti")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("decodes claims with a schema", () =>
    Effect.gen(function*() {
      const jwt = yield* JsonWebToken.JsonWebToken
      const Claims = Schema.Struct({
        ...JsonWebToken.RegisteredClaims.fields,
        role: Schema.Literals(["admin", "user"])
      })
      const token = yield* jwt.sign({ role: "user" }, {
        key: secret,
        expirationTime: "1 hour",
        protectedHeader: { alg: "HS256" }
      })
      const { payload } = yield* jwt.verify(token, secret, { algorithms: ["HS256"], schema: Claims })
      assert.strictEqual(payload.role, "user")
      const bad = yield* jwt.sign({ role: "root" }, {
        key: secret,
        expirationTime: "1 hour",
        protectedHeader: { alg: "HS256" }
      })
      const error = yield* Effect.flip(jwt.verify(bad, secret, { algorithms: ["HS256"], schema: Claims }))
      assert.strictEqual(error._tag, "ClaimValidationError")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("rejects unencoded payloads", () =>
    Effect.gen(function*() {
      const jwt = yield* JsonWebToken.JsonWebToken
      const error = yield* Effect.flip(jwt.sign({}, {
        key: secret,
        expirationTime: "1 hour",
        protectedHeader: { alg: "HS256", b64: false, crit: ["b64"] }
      }))
      assert.strictEqual(error._tag, "MalformedJwtError")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("encrypts and decrypts tokens with replicated claims", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const jwt = yield* JsonWebToken.JsonWebToken
      const { privateKey, publicKey } = yield* keys.generateKeyPair("ECDH-ES+A256KW")
      const token = yield* jwt.encrypt({ role: "admin" }, {
        key: publicKey,
        expirationTime: "1 hour",
        protectedHeader: { alg: "ECDH-ES+A256KW", enc: "A256GCM" },
        issuer: "urn:issuer",
        replicateIssuerAsHeader: true
      })
      const { payload, protectedHeader } = yield* jwt.decrypt(token, privateKey, { issuer: "urn:issuer" })
      assert.strictEqual(payload.role, "admin")
      assert.strictEqual(protectedHeader.iss, "urn:issuer")
    }).pipe(Effect.provide(JoseLive)))
})
