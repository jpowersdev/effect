import { assert, describe, it } from "@effect/vitest"
import * as Effect from "effect/Effect"
import { JsonWebKey, JsonWebSignature } from "effect/jose"
import { CryptoLive, text, utf8 } from "./utils.ts"

// RFC 7515 Appendix A.1
const rfcKey = {
  kty: "oct",
  k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
}
const rfcToken = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
  ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
  ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

const signatureAlgorithms = ["HS256", "HS512", "RS256", "PS256", "ES256", "ES384", "ES512", "EdDSA"] as const

const keyPairFor = (alg: string) =>
  alg.startsWith("HS")
    ? Effect.map(JsonWebKey.generateSecret(alg), (secret) => ({ sign: secret, verify: secret }))
    : Effect.map(JsonWebKey.generateKeyPair(alg), (pair) => ({ sign: pair.privateKey, verify: pair.publicKey }))

describe("JsonWebSignature", () => {
  it.effect("verifies the RFC 7515 A.1 example", () =>
    Effect.gen(function*() {
      const { payload, protectedHeader } = yield* JsonWebSignature.verifyCompact(rfcToken, rfcKey, {
        algorithms: ["HS256"]
      })
      assert.strictEqual(protectedHeader?.alg, "HS256")
      assert.include(text(payload), "\"iss\":\"joe\"")
    }).pipe(Effect.provide(CryptoLive)))

  for (const alg of signatureAlgorithms) {
    it.effect(`round-trips compact ${alg}`, () =>
      Effect.gen(function*() {
        const keys = yield* keyPairFor(alg)
        const jws = yield* JsonWebSignature.signCompact("hello", { key: keys.sign, protectedHeader: { alg } })
        const { payload } = yield* JsonWebSignature.verifyCompact(jws, keys.verify, { algorithms: [alg] })
        assert.strictEqual(text(payload), "hello")
      }).pipe(Effect.provide(CryptoLive)))
  }

  it.effect("rejects tampered payloads", () =>
    Effect.gen(function*() {
      const secret = utf8("a-string-secret-at-least-256-bits-long")
      const jws = yield* JsonWebSignature.signCompact("hello", { key: secret, protectedHeader: { alg: "HS256" } })
      const [header, , signature] = jws.split(".")
      const error = yield* Effect.flip(
        JsonWebSignature.verifyCompact(`${header}.aGVsbG8h.${signature}`, secret)
      )
      assert.strictEqual(error._tag, "SignatureVerificationError")
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("enforces the algorithm allow list before using the key", () =>
    Effect.gen(function*() {
      const secret = utf8("a-string-secret-at-least-256-bits-long")
      const jws = yield* JsonWebSignature.signCompact("hello", { key: secret, protectedHeader: { alg: "HS256" } })
      const error = yield* Effect.flip(JsonWebSignature.verifyCompact(jws, secret, { algorithms: ["ES256"] }))
      assert.strictEqual(error._tag, "AlgorithmNotAllowedError")
      assert.strictEqual(error._tag === "AlgorithmNotAllowedError" && error.algorithm, "HS256")
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("never accepts alg none", () =>
    Effect.gen(function*() {
      const token = "eyJhbGciOiJub25lIn0.aGVsbG8."
      const error = yield* Effect.flip(JsonWebSignature.verifyCompact(token, utf8("secret")))
      assert.strictEqual(error._tag, "UnsupportedAlgorithmError")
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("rejects keys that do not match the algorithm", () =>
    Effect.gen(function*() {
      const { privateKey, publicKey } = yield* JsonWebKey.generateKeyPair("ES256")
      const jws = yield* JsonWebSignature.signCompact("hello", { key: privateKey, protectedHeader: { alg: "ES256" } })
      const p384 = yield* JsonWebKey.generateKeyPair("ES384")
      const curve = yield* Effect.flip(JsonWebSignature.verifyCompact(jws, p384.publicKey))
      assert.strictEqual(curve._tag, "InvalidKeyError")
      const rsa = yield* JsonWebKey.generateKeyPair("RS256", { extractable: true })
      const rsaJwk = yield* JsonWebKey.exportJwk(rsa.publicKey)
      const keyType = yield* Effect.flip(JsonWebSignature.verifyCompact(jws, rsaJwk))
      assert.strictEqual(keyType._tag, "InvalidKeyError")
      const secret = yield* Effect.flip(JsonWebSignature.verifyCompact(jws, utf8("secret")))
      assert.strictEqual(secret._tag, "InvalidKeyError")
      yield* JsonWebSignature.verifyCompact(jws, publicKey)
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("supports unencoded payloads and critical extensions", () =>
    Effect.gen(function*() {
      const secret = utf8("a-string-secret-at-least-256-bits-long")
      const header = { alg: "HS256", b64: false, crit: ["b64"] }
      const jws = yield* JsonWebSignature.signFlattened("$.02", { key: secret, protectedHeader: header })
      assert.strictEqual(jws.payload, "$.02")
      const { payload } = yield* JsonWebSignature.verifyFlattened(jws, secret)
      assert.strictEqual(text(payload), "$.02")

      const custom = yield* JsonWebSignature.signCompact("x", {
        key: secret,
        protectedHeader: { alg: "HS256", crit: ["urn:example"], "urn:example": 1 },
        crit: { "urn:example": true }
      })
      const unknown = yield* Effect.flip(JsonWebSignature.verifyCompact(custom, secret))
      assert.strictEqual(unknown._tag, "UnsupportedJwsHeaderError")
      yield* JsonWebSignature.verifyCompact(custom, secret, { crit: { "urn:example": true } })
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("signs and verifies general JSON with several signers", () =>
    Effect.gen(function*() {
      const hs = yield* keyPairFor("HS256")
      const es = yield* keyPairFor("ES256")
      const jws = yield* JsonWebSignature.signGeneral("hello", [
        { key: hs.sign, protectedHeader: { alg: "HS256" } },
        { key: es.sign, protectedHeader: { alg: "ES256" } }
      ])
      assert.strictEqual(jws.signatures.length, 2)
      yield* JsonWebSignature.verifyGeneral(jws, hs.verify)
      yield* JsonWebSignature.verifyGeneral(jws, es.verify)
    }).pipe(Effect.provide(CryptoLive)))
})
