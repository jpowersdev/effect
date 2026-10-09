import * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import * as Layer from "effect/Layer"

export const WebCrypto = Crypto.make({
  randomBytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)),
  digest: (algorithm, data) =>
    Effect.promise(() => globalThis.crypto.subtle.digest(algorithm, new Uint8Array(data))).pipe(
      Effect.map((buffer) => new Uint8Array(buffer))
    ),
  keys: Crypto.makeKeyOperations(globalThis.crypto.subtle)
})

export const CryptoLive = Layer.succeed(Crypto.Crypto, WebCrypto)

export const utf8 = (input: string) => new TextEncoder().encode(input)
export const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes)
