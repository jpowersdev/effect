import type * as Crypto from "../../Crypto.ts"
import * as Effect from "../../Effect.ts"
import * as PlatformError from "../../PlatformError.ts"
import { JoseError, type JoseErrorReason } from "../JoseError.ts"

/** @internal */
export const encoder = new TextEncoder()

/** @internal */
export const decoder = new TextDecoder()

/** @internal */
export const strictDecoder = new TextDecoder("utf-8", { fatal: true })

/** @internal */
export const error = (reason: JoseErrorReason, message: string, cause?: unknown): JoseError =>
  new JoseError(cause === undefined ? { reason, message } : { reason, message, cause })

/** @internal */
export const fail = (reason: JoseErrorReason, message: string, cause?: unknown) =>
  Effect.fail(error(reason, message, cause))

/** @internal */
export const failSync = (reason: JoseErrorReason, message: string): never => {
  throw error(reason, message)
}

/**
 * Runs a synchronous validation that throws `JoseError`, capturing the error
 * in the failure channel.
 *
 * @internal
 */
export const attempt = <A>(f: () => A): Effect.Effect<A, JoseError> =>
  Effect.suspend(() => {
    try {
      return Effect.succeed(f())
    } catch (e) {
      return e instanceof JoseError ? Effect.fail(e) : Effect.die(e)
    }
  })

/** @internal */
export const mapCryptoError = <A, R>(
  effect: Effect.Effect<A, PlatformError.PlatformError | JoseError, R>,
  reason: JoseErrorReason = "CryptoFailure",
  message?: string
): Effect.Effect<A, JoseError, R> =>
  Effect.mapError(
    effect,
    (e) =>
      e instanceof JoseError ? e : error(
        PlatformError.isPlatformError(e) && e.reason._tag === "BadArgument" ? "InvalidKey" : reason,
        message ?? e.message,
        e
      )
  )

/** @internal */
export const concat = (...buffers: ReadonlyArray<Uint8Array>): Uint8Array => {
  let size = 0
  for (const buffer of buffers) size += buffer.length
  const out = new Uint8Array(size)
  let offset = 0
  for (const buffer of buffers) {
    out.set(buffer, offset)
    offset += buffer.length
  }
  return out
}

/** @internal */
export const uint32be = (value: number): Uint8Array => {
  const out = new Uint8Array(4)
  out[0] = value >>> 24
  out[1] = value >>> 16
  out[2] = value >>> 8
  out[3] = value & 0xff
  return out
}

/** @internal */
export const uint64be = (value: number): Uint8Array =>
  concat(uint32be(Math.floor(value / 2 ** 32)), uint32be(value % 2 ** 32))

/**
 * Encodes ASCII text as bytes, returning `undefined` for non-ASCII input.
 *
 * @internal
 */
export const ascii = (input: string): Uint8Array | undefined => {
  const out = new Uint8Array(input.length)
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i)
    if (code > 127) return undefined
    out[i] = code
  }
  return out
}

const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
const B64_LOOKUP = (() => {
  const table = new Int16Array(128).fill(-1)
  for (let i = 0; i < B64_ALPHABET.length; i++) table[B64_ALPHABET.charCodeAt(i)] = i
  return table
})()

/**
 * Encodes bytes or UTF-8 text as unpadded base64url.
 *
 * @internal
 */
export const b64u = (input: Uint8Array | string): string => {
  const bytes = typeof input === "string" ? encoder.encode(input) : input
  let out = ""
  let i = 0
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
    out += B64_ALPHABET[n >> 18] + B64_ALPHABET[(n >> 12) & 63] + B64_ALPHABET[(n >> 6) & 63] + B64_ALPHABET[n & 63]
  }
  const rest = bytes.length - i
  if (rest === 1) {
    const n = bytes[i] << 16
    out += B64_ALPHABET[n >> 18] + B64_ALPHABET[(n >> 12) & 63]
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8)
    out += B64_ALPHABET[n >> 18] + B64_ALPHABET[(n >> 12) & 63] + B64_ALPHABET[(n >> 6) & 63]
  }
  return out
}

/**
 * Decodes strict unpadded base64url, returning `undefined` for any character
 * outside the base64url alphabet, padding, whitespace, or an impossible
 * length.
 *
 * @internal
 */
export const b64uDecode = (input: string): Uint8Array | undefined => {
  const length = input.length
  if (length % 4 === 1) return undefined
  const out = new Uint8Array(Math.floor((length * 3) / 4))
  let buffer = 0
  let bits = 0
  let offset = 0
  for (let i = 0; i < length; i++) {
    const code = input.charCodeAt(i)
    const value = code < 128 ? B64_LOOKUP[code] : -1
    if (value === -1) return undefined
    buffer = (buffer << 6) | value
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[offset++] = (buffer >> bits) & 0xff
    }
  }
  // Non-canonical encodings carry non-zero trailing bits.
  if ((buffer & ((1 << bits) - 1)) !== 0) return undefined
  return out
}

/** @internal */
export const decodeB64u = (
  value: string,
  label: string,
  reason: JoseErrorReason
): Uint8Array => b64uDecode(value) ?? failSync(reason, `Failed to base64url decode the ${label}`)

/** @internal */
export const isObject = (input: unknown): input is Record<string, unknown> => {
  if (typeof input !== "object" || input === null || Object.prototype.toString.call(input) !== "[object Object]") {
    return false
  }
  const prototype = Object.getPrototypeOf(input)
  return prototype === null || Object.getPrototypeOf(prototype) === null
}

/** @internal */
export const isDisjoint = (...headers: ReadonlyArray<object | undefined>): boolean => {
  const seen = new Set<string>()
  for (const header of headers) {
    if (header === undefined) continue
    for (const name of Object.keys(header)) {
      if (seen.has(name)) return false
      seen.add(name)
    }
  }
  return true
}

/** @internal */
export const parseHeader = (
  encoded: string,
  reason: JoseErrorReason,
  message: string
): Record<string, unknown> => {
  let parsed: unknown
  try {
    const bytes = b64uDecode(encoded)
    if (bytes === undefined) return failSync(reason, message)
    parsed = JSON.parse(strictDecoder.decode(bytes))
  } catch {
    return failSync(reason, message)
  }
  if (!isObject(parsed)) return failSync(reason, message)
  return parsed
}

/** @internal */
export const serializeHeader = (reason: JoseErrorReason, header: unknown): [Record<string, unknown>, string] => {
  let serialized: string
  let parsed: unknown
  try {
    serialized = JSON.stringify(header)
    parsed = JSON.parse(serialized)
  } catch (cause) {
    throw error(reason, "JOSE Header is not valid JSON", cause)
  }
  if (!isObject(parsed)) return failSync(reason, "JOSE Header is not a JSON object")
  return [parsed, serialized]
}

/** @internal */
export const JWS_RECOGNIZED: Readonly<Record<string, boolean>> = { __proto__: null, b64: true } as any

/** @internal */
export const JWE_RECOGNIZED: Readonly<Record<string, boolean>> = { __proto__: null } as any

/**
 * Validates the `crit` header parameter, returning the list of critical
 * extension parameters.
 *
 * `recognizedOption` maps extension names the caller understands to whether
 * they must be integrity protected.
 *
 * @internal
 */
export const validateCrit = (
  reason: JoseErrorReason,
  recognizedDefault: Readonly<Record<string, boolean>>,
  recognizedOption: Readonly<Record<string, boolean>> | undefined,
  protectedHeader: Record<string, unknown> | undefined,
  joseHeader: Record<string, unknown>
): ReadonlyArray<string> => {
  if (joseHeader.crit !== undefined && protectedHeader?.crit === undefined) {
    return failSync(reason, "\"crit\" (Critical) Header Parameter MUST be integrity protected")
  }
  if (protectedHeader === undefined || protectedHeader.crit === undefined) return []
  const crit = protectedHeader.crit
  if (
    !Array.isArray(crit) || crit.length === 0 ||
    crit.some((input) => typeof input !== "string" || input.length === 0)
  ) {
    return failSync(reason, "\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present")
  }
  if (new Set(crit).size !== crit.length) {
    return failSync(reason, "\"crit\" (Critical) Header Parameter MUST NOT contain duplicate values")
  }
  const recognized: Record<string, boolean> = recognizedOption === undefined
    ? recognizedDefault
    : { __proto__: null, ...recognizedOption, ...recognizedDefault } as any
  for (const parameter of crit as Array<string>) {
    if (!(parameter in recognized)) {
      return failSync("NotSupported", `Extension Header Parameter "${parameter}" is not recognized`)
    }
    if (!Object.hasOwn(joseHeader, parameter) || joseHeader[parameter] === undefined) {
      return failSync(reason, `Extension Header Parameter "${parameter}" is missing`)
    }
    if (
      recognized[parameter] && (!Object.hasOwn(protectedHeader, parameter) || protectedHeader[parameter] === undefined)
    ) {
      return failSync(reason, `Extension Header Parameter "${parameter}" MUST be integrity protected`)
    }
  }
  return crit as Array<string>
}

/** @internal */
export const validateB64 = (protectedHeader: Record<string, unknown>, extensions: ReadonlyArray<string>): boolean => {
  if (extensions.includes("b64")) {
    const b64 = protectedHeader.b64
    if (typeof b64 !== "boolean") {
      return failSync("JwsInvalid", "The \"b64\" (base64url-encode payload) Header Parameter must be a boolean")
    }
    return b64
  }
  return true
}

/** @internal */
export const validateAlgorithms = (
  option: string,
  algorithms: ReadonlyArray<string> | undefined
): ReadonlySet<string> | undefined => {
  if (algorithms === undefined) return undefined
  if (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== "string")) {
    return failSync("InvalidArgument", `"${option}" option must be an array of strings`)
  }
  return new Set(algorithms)
}

/**
 * Compares two byte arrays in time independent of where they differ.
 *
 * @internal
 */
export const timingSafeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  let diff = a.length ^ b.length
  const length = Math.max(a.length, b.length)
  for (let i = 0; i < length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0)
  }
  return diff === 0
}

/** @internal */
export const isCryptoKey = (u: unknown): u is Crypto.Key =>
  typeof u === "object" && u !== null && !(u instanceof Uint8Array) &&
  "usages" in u && "algorithm" in u && "type" in u && "extractable" in u && !isObject(u)
