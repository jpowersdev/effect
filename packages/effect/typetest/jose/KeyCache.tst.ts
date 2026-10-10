import type { Effect, Layer } from "effect"
import { JsonWebKey, type JsonWebSignature } from "effect/jose"
import { describe, expect, it } from "tstyche"

declare const jwk: JsonWebKey.Jwk
declare const jws: JsonWebSignature.JsonWebSignature

describe("JsonWebKey.KeyCache", () => {
  it("never adds a requirement", () => {
    expect(jws.verifyCompact("token", jwk, { algorithms: ["ES256"] })).type.toBe<
      Effect.Effect<JsonWebSignature.VerifyResult, JsonWebSignature.VerifyError>
    >()
    expect(JsonWebKey.layerKeyCache({ capacity: 10 })).type.toBe<Layer.Layer<never>>()
  })
})
