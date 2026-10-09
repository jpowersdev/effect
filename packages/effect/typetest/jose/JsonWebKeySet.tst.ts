import type { Effect } from "effect"
import type { HttpClient } from "effect/http"
import { JsonWebKeySet } from "effect/jose"
import type { KeyValueStore } from "effect/persistence"
import { describe, expect, it } from "tstyche"

type Services<T> = T extends Effect.Effect<infer _A, infer _E, infer R> ? R : never
type ResolverError<T> = T extends Effect.Effect<JsonWebKeySet.Resolver<infer E>, infer _E, infer _R> ? E : never

describe("JsonWebKeySet.makeRemote", () => {
  it("requires only HttpClient with memory storage", () => {
    expect<Services<ReturnType<typeof JsonWebKeySet.makeRemote<{}>>>>().type.toBe<HttpClient.HttpClient>()
    const remote = JsonWebKeySet.makeRemote("https://issuer.example/jwks", { storage: "memory" })
    expect<Services<typeof remote>>().type.toBe<HttpClient.HttpClient>()
    expect<ResolverError<typeof remote>>().type.toBe<JsonWebKeySet.RemoteSelectError>()
  })

  it("adds KeyValueStore and its error when keyValueStore storage is selected", () => {
    const remote = JsonWebKeySet.makeRemote("https://issuer.example/jwks", { storage: "keyValueStore" })
    expect<Services<typeof remote>>().type.toBe<HttpClient.HttpClient | KeyValueStore.KeyValueStore>()
    expect<ResolverError<typeof remote>>().type.toBe<
      JsonWebKeySet.RemoteSelectError | KeyValueStore.KeyValueStoreError
    >()
  })
})
