import type { Crypto, Effect, Layer } from "effect"
import { JsonWebKey, JsonWebSignature } from "effect/jose"
import { describe, expect, it } from "tstyche"

declare const jwk: JsonWebKey.Jwk

describe("JsonWebKey.KeyCache", () => {
  it("never adds a requirement", () => {
    expect(JsonWebSignature.verifyCompact("token", jwk)).type.toBe<
      Effect.Effect<JsonWebSignature.VerifyResult, JsonWebSignature.VerifyError, Crypto.Crypto>
    >()
    expect(JsonWebKey.layerKeyCache({ capacity: 10 })).type.toBe<Layer.Layer<never>>()
  })
})
