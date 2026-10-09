import * as Crypto from "../../Crypto.ts"
import * as Effect from "../../Effect.ts"
import type { JoseError } from "../JoseError.ts"
import type { Usage } from "./algorithms.ts"
import { attempt, b64uDecode, fail, failSync, isCryptoKey, isObject, mapCryptoError } from "./shared.ts"

/** @internal */
export interface KeyEntry {
  readonly alg: string
  readonly kty: ReadonlyArray<string>
  readonly secret: boolean
  readonly key: Crypto.KeyAlgorithm | undefined
  readonly resolve?: (jwk: { readonly kty?: unknown; readonly crv?: unknown }) => Crypto.KeyAlgorithm
  readonly usages: readonly [ReadonlyArray<Crypto.KeyUsage>, ReadonlyArray<Crypto.KeyUsage>]
  readonly ops?: readonly [Crypto.KeyUsage | undefined, Crypto.KeyUsage | undefined]
}

/** @internal */
export const normalizeJwk = (jwk: Record<string, unknown>): Record<string, unknown> => {
  const normalized: Record<string, unknown> = { ...jwk }
  if (normalized.ext !== undefined && typeof normalized.ext !== "boolean") {
    return failSync("InvalidKey", "\"ext\" (Extractable) Parameter must be a boolean")
  }
  if (normalized.key_ops !== undefined) {
    const value = normalized.key_ops
    const keyOps = Array.isArray(value) ? [...value] : undefined
    if (!keyOps || keyOps.some((op) => typeof op !== "string") || new Set(keyOps).size !== keyOps.length) {
      return failSync("InvalidKey", "\"key_ops\" (Key Operations) Parameter must be an array of unique strings")
    }
    normalized.key_ops = keyOps
  }
  return normalized
}

const jwkMatchesOp = (entry: KeyEntry, jwk: Record<string, unknown>, usage: Usage) => {
  if (jwk.use !== undefined) {
    const expected = usage === "sign" || usage === "verify" ? "sig" : "enc"
    if (jwk.use !== expected) {
      failSync("InvalidKey", `Invalid key for this operation, its "use" must be "${expected}" when present`)
    }
  }
  if (jwk.alg !== undefined && jwk.alg !== entry.alg) {
    failSync("InvalidKey", `Invalid key for this operation, its "alg" must be "${entry.alg}" when present`)
  }
  if (Array.isArray(jwk.key_ops)) {
    const expected = usage === "encrypt" || usage === "decrypt"
      ? entry.ops?.[usage === "encrypt" ? 0 : 1]
      : usage
    if (expected && !jwk.key_ops.includes(expected)) {
      failSync("InvalidKey", `Invalid key for this operation, its "key_ops" must include "${expected}" when present`)
    }
  }
}

const describe = (u: unknown): string =>
  u === null || u === undefined
    ? ` Received ${u}`
    : typeof u === "object" && (u as any).constructor?.name
    ? ` Received an instance of ${(u as any).constructor.name}`
    : ` Received type ${typeof u}`

/**
 * Converts any supported key input into a platform key or raw secret bytes
 * suitable for `entry`, enforcing key type, `use`, `alg`, and `key_ops`.
 *
 * @internal
 */
export const prepareKey = (
  entry: KeyEntry,
  key: unknown,
  usage: Usage
): Effect.Effect<Crypto.Key | Uint8Array, JoseError, Crypto.Crypto> =>
  Effect.suspend(() => {
    const isPrivate = usage === "decrypt" || usage === "sign"
    if (entry.secret && key instanceof Uint8Array) return Effect.succeed(key)
    if (isObject(key)) {
      return attempt(() => {
        const jwk = normalizeJwk(key)
        if (typeof jwk.kty !== "string") {
          return failSync(
            "InvalidKey",
            `Key for the ${entry.alg} algorithm must be a Key or JSON Web Key.${describe(key)}`
          )
        }
        const valid = entry.secret
          ? jwk.kty === "oct" && typeof jwk.k === "string"
          : jwk.kty !== "oct" && (isPrivate ? typeof jwk.d === "string" : jwk.d === undefined)
        if (!valid) {
          failSync(
            "InvalidKey",
            entry.secret
              ? "JSON Web Key for symmetric algorithms must have JWK \"kty\" (Key Type) equal to \"oct\" and the JWK \"k\" (Key Value) present"
              : `JSON Web Key for this operation must be a ${isPrivate ? "private" : "public"} JWK`
          )
        }
        jwkMatchesOp(entry, jwk, usage)
        return jwk
      }).pipe(Effect.flatMap((jwk): Effect.Effect<Crypto.Key | Uint8Array, JoseError, Crypto.Crypto> => {
        if (jwk.kty === "oct") {
          const bytes = b64uDecode(jwk.k as string)
          return bytes === undefined
            ? fail("JwkInvalid", "Failed to base64url decode the \"k\" (Key Value) Parameter")
            : Effect.succeed(bytes)
        }
        return jwkToKey(entry, { ...jwk, alg: entry.alg } as unknown as Crypto.JwkData)
      }))
    }
    if (!isCryptoKey(key)) {
      return fail(
        "InvalidKey",
        `Key for the ${entry.alg} algorithm must be a Key${
          entry.secret ? ", JSON Web Key, or Uint8Array" : " or JSON Web Key"
        }.${describe(key)}`
      )
    }
    const expectedType = entry.secret ? "secret" : isPrivate ? "private" : "public"
    if (key.type !== expectedType) {
      return fail("InvalidKey", `Key instances must be of type "${expectedType}" for the ${entry.alg} algorithm`)
    }
    return Effect.succeed(key)
  })

/**
 * Imports a JSON Web Key for `entry`, using its `key_ops` when present.
 *
 * @internal
 */
export const jwkToKey = (
  entry: KeyEntry,
  jwk: Crypto.JwkData,
  extractable?: boolean
): Effect.Effect<Crypto.Key, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    if (!entry.kty.includes(jwk.kty)) {
      return yield* fail("NotSupported", "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value")
    }
    const algorithm = entry.resolve !== undefined
      ? yield* attempt(() => entry.resolve!({ kty: jwk.kty, crv: jwk.crv }))
      : entry.key
    if (algorithm === undefined) {
      return yield* fail("NotSupported", "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value")
    }
    const isPrivate = typeof jwk.d === "string"
    const { alg: _alg, use: _use, ...keyData } = jwk as Record<string, unknown>
    const ext = extractable ?? (keyData.ext as boolean | undefined)
    if (ext !== undefined) keyData.ext = ext
    else delete keyData.ext
    const crypto = yield* Crypto.Crypto
    const usages = (jwk.key_ops as ReadonlyArray<Crypto.KeyUsage> | undefined) ?? entry.usages[isPrivate ? 1 : 0]
    return yield* mapCryptoError(
      crypto.importKey("jwk", keyData as Crypto.JwkData, algorithm, { extractable: ext ?? !isPrivate, usages }),
      "JwkInvalid",
      "Invalid JSON Web Key"
    )
  })

const unusable = (name: string | number, prop = "algorithm.name") =>
  failSync("InvalidKey", `Key does not support this operation, its ${prop} must be ${name}`)

/** @internal */
export const checkUsage = (key: Crypto.Key, usage: Crypto.KeyUsage | undefined) => {
  if (usage && !key.usages.includes(usage)) {
    failSync("InvalidKey", `Key does not support this operation, its usages must include ${usage}.`)
  }
}

/** @internal */
export const checkCryptoKey = (key: Crypto.Key, expected: Crypto.KeyAlgorithm, usage: Crypto.KeyUsage | undefined) => {
  const algorithm = key.algorithm
  if (algorithm.name !== expected.name) unusable(expected.name)
  if ("hash" in expected && expected.hash !== undefined && algorithm.hash !== expected.hash) {
    unusable(expected.hash, "algorithm.hash")
  }
  if ("namedCurve" in expected && algorithm.namedCurve !== expected.namedCurve) {
    unusable(expected.namedCurve, "algorithm.namedCurve")
  }
  if ("length" in expected && expected.length !== undefined && algorithm.length !== expected.length) {
    unusable(expected.length, "algorithm.length")
  }
  checkUsage(key, usage)
}

/** @internal */
export const checkModulusLength = (alg: string, key: Crypto.Key) => {
  const { modulusLength } = key.algorithm
  if (typeof modulusLength !== "number" || modulusLength < 2048) {
    failSync("InvalidKey", `${alg} requires key modulusLength to be 2048 bits or larger`)
  }
}

/**
 * Imports raw secret bytes for `expected`, or checks that an existing key is
 * bound to `expected` and permits `usage`.
 *
 * @internal
 */
export const rawKey = (
  key: Crypto.Key | Uint8Array,
  expected: Crypto.KeyAlgorithm,
  usage: Crypto.KeyUsage,
  extractable = false
): Effect.Effect<Crypto.Key, JoseError, Crypto.Crypto> =>
  Effect.gen(function*() {
    let k: Crypto.Key
    if (key instanceof Uint8Array) {
      const crypto = yield* Crypto.Crypto
      k = yield* mapCryptoError(
        crypto.importKey("raw", key, expected, { extractable, usages: [usage] }),
        "InvalidKey",
        "Invalid key material for this algorithm"
      )
    } else {
      k = key
    }
    yield* attempt(() => checkCryptoKey(k, expected, usage))
    return k
  })
