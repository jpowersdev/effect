import { assert, describe, it } from "@effect/vitest"
import * as Effect from "effect/Effect"
import { type JsonWebAlgorithm, JsonWebKey, JsonWebSignature } from "effect/jose"
import * as Redacted from "effect/Redacted"
import { JoseLive, text, utf8 } from "./utils.ts"

// RFC 7515 Appendix A.1
const rfcKey = {
  kty: "oct",
  k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
}
const rfcToken = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
  ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
  ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

const signatureAlgorithms = ["HS256", "HS512", "RS256", "PS256", "ES256", "ES384", "ES512", "EdDSA"] as const

const keyPairFor = Effect.fnUntraced(function*(alg: JsonWebAlgorithm.SignatureAlgorithm) {
  const keys = yield* JsonWebKey.JsonWebKey
  if (alg.startsWith("HS")) {
    const secret = yield* keys.generateSecret(alg)
    return { sign: secret, verify: secret }
  }
  const pair = yield* keys.generateKeyPair(alg)
  return { sign: pair.privateKey, verify: pair.publicKey }
})

describe("JsonWebSignature", () => {
  it.effect("verifies the RFC 7515 A.1 example", () =>
    Effect.gen(function*() {
      const jws = yield* JsonWebSignature.JsonWebSignature
      const { payload, protectedHeader } = yield* jws.verifyCompact(rfcToken, rfcKey, {
        algorithms: ["HS256"]
      })
      assert.strictEqual(protectedHeader?.alg, "HS256")
      assert.include(text(payload), "\"iss\":\"joe\"")
    }).pipe(Effect.provide(JoseLive)))

  for (const alg of signatureAlgorithms) {
    it.effect(`round-trips compact ${alg}`, () =>
      Effect.gen(function*() {
        const jws = yield* JsonWebSignature.JsonWebSignature
        const pair = yield* keyPairFor(alg)
        const token = yield* jws.signCompact("hello", { key: pair.sign, protectedHeader: { alg } })
        const { payload } = yield* jws.verifyCompact(token, pair.verify, { algorithms: [alg] })
        assert.strictEqual(text(payload), "hello")
      }).pipe(Effect.provide(JoseLive)))
  }

  it.effect("rejects tampered payloads", () =>
    Effect.gen(function*() {
      const jws = yield* JsonWebSignature.JsonWebSignature
      const secret = utf8("a-string-secret-at-least-256-bits-long")
      const token = yield* jws.signCompact("hello", { key: secret, protectedHeader: { alg: "HS256" } })
      const [header, , signature] = Redacted.value(token).split(".")
      const error = yield* Effect.flip(
        jws.verifyCompact(`${header}.aGVsbG8h.${signature}`, secret, { algorithms: ["HS256"] })
      )
      assert.strictEqual(error._tag, "SignatureVerificationError")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("enforces the algorithm allow list before using the key", () =>
    Effect.gen(function*() {
      const jws = yield* JsonWebSignature.JsonWebSignature
      const secret = utf8("a-string-secret-at-least-256-bits-long")
      const token = yield* jws.signCompact("hello", { key: secret, protectedHeader: { alg: "HS256" } })
      const error = yield* Effect.flip(jws.verifyCompact(token, secret, { algorithms: ["ES256"] }))
      assert.strictEqual(error._tag, "AlgorithmNotAllowedError")
      assert.strictEqual(error._tag === "AlgorithmNotAllowedError" && error.algorithm, "HS256")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("never accepts alg none", () =>
    Effect.gen(function*() {
      const jws = yield* JsonWebSignature.JsonWebSignature
      const token = "eyJhbGciOiJub25lIn0.aGVsbG8."
      const notAllowed = yield* Effect.flip(
        jws.verifyCompact(token, utf8("secret"), { algorithms: ["HS256"] })
      )
      assert.strictEqual(notAllowed._tag, "AlgorithmNotAllowedError")
      // Even if a caller forces "none" into the allow list, it is not a supported algorithm.
      const unsupported = yield* Effect.flip(
        jws.verifyCompact(token, utf8("secret"), { algorithms: ["none" as never] })
      )
      assert.strictEqual(unsupported._tag, "UnsupportedAlgorithmError")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("rejects keys that do not match the algorithm", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const jws = yield* JsonWebSignature.JsonWebSignature
      const { privateKey, publicKey } = yield* keys.generateKeyPair("ES256")
      const token = yield* jws.signCompact("hello", { key: privateKey, protectedHeader: { alg: "ES256" } })
      const p384 = yield* keys.generateKeyPair("ES384")
      const curve = yield* Effect.flip(jws.verifyCompact(token, p384.publicKey))
      assert.strictEqual(curve._tag, "InvalidKeyError")
      const rsa = yield* keys.generateKeyPair("RS256", { extractable: true })
      const rsaJwk = yield* keys.exportJwk(rsa.publicKey)
      const keyType = yield* Effect.flip(jws.verifyCompact(token, rsaJwk, { algorithms: ["ES256"] }))
      assert.strictEqual(keyType._tag, "InvalidKeyError")
      const secret = yield* Effect.flip(jws.verifyCompact(token, utf8("secret"), { algorithms: ["ES256"] }))
      assert.strictEqual(secret._tag, "InvalidKeyError")
      yield* jws.verifyCompact(token, publicKey)
    }).pipe(Effect.provide(JoseLive)))

  it.effect("supports unencoded payloads and critical extensions", () =>
    Effect.gen(function*() {
      const jws = yield* JsonWebSignature.JsonWebSignature
      const secret = utf8("a-string-secret-at-least-256-bits-long")
      const header = { alg: "HS256", b64: false, crit: ["b64"] } as const
      const signed = yield* jws.signFlattened("$.02", { key: secret, protectedHeader: header })
      assert.strictEqual(signed.payload, "$.02")
      const { payload } = yield* jws.verifyFlattened(signed, secret, { algorithms: ["HS256"] })
      assert.strictEqual(text(payload), "$.02")

      const custom = yield* jws.signCompact("x", {
        key: secret,
        protectedHeader: { alg: "HS256", crit: ["urn:example"], "urn:example": 1 },
        crit: { "urn:example": true }
      })
      const unknown = yield* Effect.flip(jws.verifyCompact(custom, secret, { algorithms: ["HS256"] }))
      assert.strictEqual(unknown._tag, "UnsupportedJwsHeaderError")
      yield* jws.verifyCompact(custom, secret, { algorithms: ["HS256"], crit: { "urn:example": true } })
    }).pipe(Effect.provide(JoseLive)))

  it.effect("signs and verifies general JSON with several signers", () =>
    Effect.gen(function*() {
      const jws = yield* JsonWebSignature.JsonWebSignature
      const hs = yield* keyPairFor("HS256")
      const es = yield* keyPairFor("ES256")
      const signed = yield* jws.signGeneral("hello", [
        { key: hs.sign, protectedHeader: { alg: "HS256" } },
        { key: es.sign, protectedHeader: { alg: "ES256" } }
      ])
      assert.strictEqual(signed.signatures.length, 2)
      yield* jws.verifyGeneral(signed, hs.verify, { algorithms: ["HS256", "ES256"] })
      yield* jws.verifyGeneral(signed, es.verify, { algorithms: ["HS256", "ES256"] })
    }).pipe(Effect.provide(JoseLive)))
})
