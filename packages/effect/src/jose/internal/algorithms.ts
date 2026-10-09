import type * as Crypto from "../../Crypto.ts"
import { UnsupportedAlgorithmError } from "../JsonWebAlgorithm.ts"
import { raise } from "./shared.ts"

const unsupported = (message: string, algorithm?: unknown) =>
  raise(
    new UnsupportedAlgorithmError(typeof algorithm === "string" ? { algorithm, message } : { message })
  )

/** @internal */
export type Usage = "sign" | "verify" | "encrypt" | "decrypt"

/** @internal */
export interface JwsEntry {
  readonly alg: string
  readonly kty: ReadonlyArray<string>
  readonly crv?: string
  readonly secret: boolean
  readonly key: Crypto.KeyAlgorithm
  readonly signing: Crypto.SignAlgorithm
  readonly usages: readonly [ReadonlyArray<Crypto.KeyUsage>, ReadonlyArray<Crypto.KeyUsage>]
  readonly minRsaBits?: number
}

const sig = [["verify"], ["sign"]] as const

const hmac = (alg: string, bits: number): JwsEntry => ({
  alg,
  kty: ["oct"],
  secret: true,
  key: { name: "HMAC", hash: `SHA-${bits}` as Crypto.DigestAlgorithm },
  signing: { name: "HMAC" },
  usages: sig
})

const rsa = (alg: string, bits: number, saltLength?: number): JwsEntry => ({
  alg,
  kty: ["RSA"],
  secret: false,
  key: { name: saltLength ? "RSA-PSS" : "RSASSA-PKCS1-v1_5", hash: `SHA-${bits}` as Crypto.DigestAlgorithm },
  signing: saltLength ? { name: "RSA-PSS", saltLength } : { name: "RSASSA-PKCS1-v1_5" },
  usages: sig,
  minRsaBits: 2048
})

const ecdsa = (alg: string, crv: Crypto.NamedCurve, bits: number): JwsEntry => ({
  alg,
  kty: ["EC"],
  crv,
  secret: false,
  key: { name: "ECDSA", namedCurve: crv },
  signing: { name: "ECDSA", hash: `SHA-${bits}` as Crypto.DigestAlgorithm },
  usages: sig
})

const eddsa = (alg: string): JwsEntry => ({
  alg,
  kty: ["OKP"],
  crv: "Ed25519",
  secret: false,
  key: { name: "Ed25519" },
  signing: { name: "Ed25519" },
  usages: sig
})

/** @internal */
export const JWS: Readonly<Record<string, JwsEntry>> = Object.assign(Object.create(null), {
  HS256: hmac("HS256", 256),
  HS384: hmac("HS384", 384),
  HS512: hmac("HS512", 512),
  RS256: rsa("RS256", 256),
  RS384: rsa("RS384", 384),
  RS512: rsa("RS512", 512),
  PS256: rsa("PS256", 256, 32),
  PS384: rsa("PS384", 384, 48),
  PS512: rsa("PS512", 512, 64),
  ES256: ecdsa("ES256", "P-256", 256),
  ES384: ecdsa("ES384", "P-384", 384),
  ES512: ecdsa("ES512", "P-521", 512),
  EdDSA: eddsa("EdDSA"),
  Ed25519: eddsa("Ed25519")
})

/** @internal */
export const jwsAlgorithm = (alg: unknown): JwsEntry =>
  (typeof alg === "string" ? JWS[alg] : undefined) ??
    unsupported(`alg ${String(alg)} is not supported`, alg)

/** @internal */
export type JweMode =
  | "direct-encryption"
  | "key-encryption"
  | "direct-key-agreement"
  | "key-agreement-with-key-wrapping"
  | "key-wrapping"

/** @internal */
export interface JweEntry {
  readonly alg: string
  readonly kty: ReadonlyArray<string>
  readonly mode: JweMode
  readonly secret: boolean
  readonly key: Crypto.KeyAlgorithm | undefined
  readonly usages: readonly [ReadonlyArray<Crypto.KeyUsage>, ReadonlyArray<Crypto.KeyUsage>]
  readonly ops: readonly [Crypto.KeyUsage | undefined, Crypto.KeyUsage | undefined]
  readonly resolve?: (jwk: { readonly kty?: unknown; readonly crv?: unknown }) => Crypto.KeyAlgorithm
  readonly minRsaBits?: number
}

const wrap = [["encrypt", "wrapKey"], ["decrypt", "unwrapKey"]] as const
const derive = [[], ["deriveBits"]] as const
const none = [[], []] as const

const rsaes = (alg: string, hash: Crypto.DigestAlgorithm): JweEntry => ({
  alg,
  kty: ["RSA"],
  mode: "key-encryption",
  secret: false,
  key: { name: "RSA-OAEP", hash },
  usages: wrap,
  ops: ["wrapKey", "unwrapKey"],
  minRsaBits: 2048
})

const ecdh = (alg: string, mode: JweMode): JweEntry => ({
  alg,
  kty: ["EC", "OKP"],
  mode,
  secret: false,
  key: undefined,
  resolve: ({ kty, crv }) => {
    if (crv === "X25519") return { name: "X25519" }
    if (kty === "OKP" || (crv !== "P-256" && crv !== "P-384" && crv !== "P-521")) {
      return unsupported(`ECDH with curve ${String(crv)} is not supported`)
    }
    return { name: "ECDH", namedCurve: crv }
  },
  usages: derive,
  ops: [undefined, "deriveBits"]
})

const aeskw = (alg: string, bits: number, gcm = false): JweEntry => ({
  alg,
  kty: ["oct"],
  mode: "key-wrapping",
  secret: true,
  key: { name: gcm ? "AES-GCM" : "AES-KW", length: bits },
  usages: none,
  ops: gcm ? ["encrypt", "decrypt"] : ["wrapKey", "unwrapKey"]
})

const pbes2 = (alg: string): JweEntry => ({
  alg,
  kty: ["oct"],
  mode: "key-wrapping",
  secret: true,
  key: { name: "PBKDF2" },
  usages: none,
  ops: ["deriveBits", "deriveBits"]
})

/** @internal */
export const JWE: Readonly<Record<string, JweEntry>> = Object.assign(Object.create(null), {
  dir: {
    alg: "dir",
    kty: ["oct"],
    mode: "direct-encryption",
    secret: true,
    key: undefined,
    usages: none,
    ops: ["encrypt", "decrypt"]
  } satisfies JweEntry,
  "RSA-OAEP": rsaes("RSA-OAEP", "SHA-1"),
  "RSA-OAEP-256": rsaes("RSA-OAEP-256", "SHA-256"),
  "RSA-OAEP-384": rsaes("RSA-OAEP-384", "SHA-384"),
  "RSA-OAEP-512": rsaes("RSA-OAEP-512", "SHA-512"),
  "ECDH-ES": ecdh("ECDH-ES", "direct-key-agreement"),
  "ECDH-ES+A128KW": ecdh("ECDH-ES+A128KW", "key-agreement-with-key-wrapping"),
  "ECDH-ES+A192KW": ecdh("ECDH-ES+A192KW", "key-agreement-with-key-wrapping"),
  "ECDH-ES+A256KW": ecdh("ECDH-ES+A256KW", "key-agreement-with-key-wrapping"),
  A128KW: aeskw("A128KW", 128),
  A192KW: aeskw("A192KW", 192),
  A256KW: aeskw("A256KW", 256),
  A128GCMKW: aeskw("A128GCMKW", 128, true),
  A192GCMKW: aeskw("A192GCMKW", 192, true),
  A256GCMKW: aeskw("A256GCMKW", 256, true),
  "PBES2-HS256+A128KW": pbes2("PBES2-HS256+A128KW"),
  "PBES2-HS384+A192KW": pbes2("PBES2-HS384+A192KW"),
  "PBES2-HS512+A256KW": pbes2("PBES2-HS512+A256KW")
})

/** @internal */
export interface EncEntry {
  readonly alg: string
  readonly kty: ReadonlyArray<string>
  readonly secret: true
  readonly key: Crypto.KeyAlgorithm
  readonly usages: readonly [ReadonlyArray<Crypto.KeyUsage>, ReadonlyArray<Crypto.KeyUsage>]
  readonly ops: readonly [Crypto.KeyUsage, Crypto.KeyUsage]
  readonly cekBits: number
  readonly ivBits: number
  readonly cbc: boolean
}

const contentEncryption = (alg: string, bits: number, cbc = false): EncEntry => ({
  alg,
  kty: ["oct"],
  secret: true,
  key: { name: cbc ? "AES-CBC" : "AES-GCM", length: bits },
  usages: none,
  ops: ["encrypt", "decrypt"],
  cekBits: bits,
  ivBits: cbc ? 128 : 96,
  cbc
})

/** @internal */
export const ENC: Readonly<Record<string, EncEntry>> = Object.assign(Object.create(null), {
  A128GCM: contentEncryption("A128GCM", 128),
  A192GCM: contentEncryption("A192GCM", 192),
  A256GCM: contentEncryption("A256GCM", 256),
  "A128CBC-HS256": contentEncryption("A128CBC-HS256", 256, true),
  "A192CBC-HS384": contentEncryption("A192CBC-HS384", 384, true),
  "A256CBC-HS512": contentEncryption("A256CBC-HS512", 512, true)
})

/** @internal */
export const jweAlgorithm = (alg: unknown): JweEntry =>
  (typeof alg === "string" ? JWE[alg] : undefined) ??
    unsupported("Invalid or unsupported \"alg\" (JWE Algorithm) header value", alg)

/** @internal */
export const jweEncryption = (enc: unknown): EncEntry =>
  (typeof enc === "string" ? ENC[enc] : undefined) ??
    unsupported("Invalid or unsupported \"enc\" (JWE Encryption Algorithm) header value", enc)

/** @internal */
export const isCekTransport = (entry: JweEntry): boolean =>
  entry.mode === "key-wrapping" || entry.mode === "key-encryption" ||
  entry.mode === "key-agreement-with-key-wrapping"
