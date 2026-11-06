/**
 * The caller a permission check is about.
 *
 * A principal is authenticated, a guest, or the system. Authenticated
 * principals carry a subject, the application's own attributes (roles,
 * memberships, capabilities), an optional actor when someone acts on the
 * subject's behalf, optional limits on which actions the request may use, and
 * an optional revision for cache invalidation.
 *
 * Applications provide the principal as their own `Context.Service`, so the
 * attribute type is theirs and handlers that check permissions require it. The
 * subject id type can be the application's own too, such as a branded id.
 *
 * An attribute that costs a lookup can be given as an effect: it is loaded
 * the first time a rule or handler reads it, then kept for the life of the
 * principal. See {@link Lazy}.
 *
 * **Example** (Declaring the application's principal)
 *
 * ```ts
 * import { Context, Schema } from "effect"
 * import type { Principal } from "effect/permission"
 *
 * class Member extends Schema.Class<Member>("app/Member")({
 *   orgId: Schema.String,
 *   role: Schema.Literals(["owner", "member"])
 * }) {}
 *
 * class CurrentPrincipal extends Context.Service<
 *   CurrentPrincipal,
 *   Principal.Principal<Member>
 * >()("app/CurrentPrincipal") {}
 * ```
 *
 * @stability experimental
 * @since 4.1.3
 */
import type * as Brand from "../Brand.ts"
import * as Effect from "../Effect.ts"
import * as Effectable from "../Effectable.ts"
import { dual, identity } from "../Function.ts"
import * as Predicate from "../Predicate.ts"
import type * as Types from "../Types.ts"
import type * as Condition from "./Condition.ts"
import * as PermissionError from "./PermissionError.ts"

const LazyTypeId = "~effect/permission/Principal/Lazy" as const

/**
 * Who a principal is: a user or a service, identified by an id.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Subject<out Id extends string = string> {
  readonly kind: "user" | "service"
  readonly id: Id
}

/**
 * A signed-in principal with application-defined attributes.
 *
 * **Details**
 *
 * - `actor` is set when someone else acts on the subject's behalf, for example
 *   a support user impersonating them.
 * - `limits` restricts which actions this request may use, whatever the rules
 *   allow. Every limit must include the action. Use it for credentials that are
 *   narrower than the person, such as links sent by text message or API keys.
 * - `revision` changes whenever the subject's access changes, so cached
 *   decisions keyed on it go stale immediately.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Authenticated<out A, out Id extends string = string> {
  readonly _tag: "Authenticated"
  readonly subject: Subject<Id>
  readonly attributes: A
  readonly actor: Subject | undefined
  readonly limits: ReadonlyArray<ReadonlyArray<string>>
  readonly revision: string | undefined
}

/**
 * An anonymous principal. Guests are denied every action.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Guest {
  readonly _tag: "Guest"
}

/**
 * The application acting on its own authority, for background jobs and
 * internal tasks. System principals are allowed every action.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface System {
  readonly _tag: "System"
  readonly name: string
}

/**
 * The caller a permission check is about.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Principal<A, Id extends string = string> = Authenticated<A, Id> | Guest | System

/**
 * The fields of an authenticated principal that rules can reference.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Fields<A, Id extends string = string> {
  readonly subject: Subject<Id>
  readonly attributes: A
  readonly actor: Subject | undefined
}

/**
 * References to the fields of an authenticated principal, as received by rule
 * definitions.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Refs<A, Id extends string = string> = Condition.Refs<Fields<A, Id>>

/**
 * An attribute given to {@link make} as an effect. It is loaded the first time
 * something reads it, then kept for the life of the principal.
 *
 * **Details**
 *
 * A lazy attribute is an effect, so handlers read it with `yield*`. Rules
 * refer to it like any other attribute, and the authorizer loads it only when
 * a condition reaches it: for a super admin,
 * `Condition.or(principal.attributes.isSuperAdmin, ...)` never loads what comes
 * after.
 *
 * Callers that read it at the same time share one load. A load that fails is
 * logged and fails with `PermissionUnavailable`, and that failure is kept too,
 * so every check in a request gets the same answer.
 *
 * **Gotchas**
 *
 * The value is kept as long as the principal is. Build a principal for each
 * request, as authentication middleware does, so a change to the attribute
 * shows up on the next request.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Lazy<out A> extends Effect.Effect<A, PermissionError.PermissionUnavailable> {
  readonly [LazyTypeId]: {
    readonly _A: Types.Covariant<A>
  }
}

/**
 * The value of an attribute: what a {@link Lazy} attribute loads, or the
 * attribute itself.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
// Matching on the one property is much cheaper than matching `Lazy`, which
// would compare every member of `Effect`
export type Loaded<A> = A extends { readonly [LazyTypeId]: { readonly _A: Types.Covariant<infer B> } } ? B : A

/**
 * The attributes of a principal built by {@link make}: each top-level field
 * given as an effect becomes {@link Lazy}.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type Attributes<A> = [LazyKeys<A>] extends [never] ? A
  : { [K in keyof A]: A[K] extends Effect.Effect<infer B, any, never> ? Lazy<B> : A[K] }

// Rejects an attribute effect that requires services, at the attribute
type WithoutServices<A> = {
  readonly [K in keyof A]: A[K] extends Effect.Effect<infer B, infer E, infer R> ?
    [R] extends [never] ? unknown : Effect.Effect<B, E, never>
    : unknown
}

type LazyKeys<A> = {
  [K in keyof A]-?: A[K] extends Effect.Effect<any, any, never> ? K : never
}[keyof A]

class LazyImpl<A> extends Effectable.Class<A, PermissionError.PermissionUnavailable> {
  readonly [LazyTypeId] = { _A: identity }
  readonly load: Effect.Effect<A, PermissionError.PermissionUnavailable>
  cached: Effect.Effect<A, PermissionError.PermissionUnavailable> | undefined
  constructor(load: Effect.Effect<A, PermissionError.PermissionUnavailable>) {
    super()
    this.load = load
  }
  asEffect(): Effect.Effect<A, PermissionError.PermissionUnavailable> {
    // Two first reads may each make a cached effect, but only the first one
    // kept is ever run
    return Effect.suspend(() =>
      this.cached ?? Effect.flatMap(Effect.cached(this.load), (cached) => (this.cached ??= cached))
    )
  }
  override toJSON() {
    return { _id: "Principal.Lazy" }
  }
}

/** @internal */
export const isLazy = (u: unknown): u is Lazy<unknown> => Predicate.hasProperty(u, LazyTypeId)

// Replaces each top-level effect with one that loads once. The attributes are
// copied, keeping their prototype, only if there is one to replace.
const cacheEffects = <A>(attributes: A): Attributes<A> => {
  if (!Predicate.isObject(attributes)) return attributes as Attributes<A>
  let out: Record<string, unknown> | undefined
  for (const key of Object.keys(attributes)) {
    const value = attributes[key]
    if (!Effect.isEffect(value) || isLazy(value)) continue
    out ??= Object.assign(Object.create(Object.getPrototypeOf(attributes)), attributes) as Record<string, unknown>
    // `make` only accepts effects without requirements
    const load = value as Effect.Effect<unknown, unknown>
    out[key] = new LazyImpl(load.pipe(
      Effect.catch((cause) =>
        Effect.logWarning(`Principal attribute "${key}" failed to load`, cause).pipe(
          Effect.andThen(Effect.fail(new PermissionError.PermissionUnavailable()))
        )
      )
    ))
  }
  return (out ?? attributes) as Attributes<A>
}

const toSubject = <Id extends string>(subject: Subject<Id> | Id): Subject<Id> =>
  typeof subject === "string" ? { kind: "user", id: subject } : subject

// A literal subject widens to `string`, like `let`; a branded id keeps its brand
type IdOf<Id extends string> = Id extends Brand.Brand<any> ? Id : string

/**
 * Creates an authenticated principal. A string subject is a user id. A
 * branded subject id, such as a `Schema.brand` id, becomes the principal's id
 * type; any other id is a `string`.
 *
 * **Details**
 *
 * A top-level attribute given as an effect becomes {@link Lazy}: it runs the
 * first time a rule or handler reads it, and its result is kept. The effect
 * can't require services, so close over them where the principal is built.
 *
 * **Gotchas**
 *
 * - Only top-level attributes are checked for effects. To load nested data
 *   lazily, load the whole object: `org: loadOrg(id)`.
 * - Every effect counts, including `Exit` values and errors.
 *
 * **Example** (Creating a principal)
 *
 * ```ts
 * import { Principal } from "effect/permission"
 *
 * const principal = Principal.make({
 *   subject: "profile_1",
 *   attributes: { orgId: "org_1", role: "member" as const }
 * })
 * ```
 *
 * **Example** (Loading an attribute only when a rule needs it)
 *
 * ```ts
 * import { Effect } from "effect"
 * import { Principal } from "effect/permission"
 *
 * declare const managedUnitIds: (profileId: string) => Effect.Effect<ReadonlyArray<string>>
 *
 * const principal = Principal.make({
 *   subject: "profile_1",
 *   attributes: {
 *     isSuperAdmin: false,
 *     managedUnitIds: managedUnitIds("profile_1")
 *   }
 * })
 *
 * const program = Effect.gen(function*() {
 *   const unitIds = yield* principal.attributes.managedUnitIds
 *   yield* Effect.log(unitIds)
 * })
 * ```
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const make = <A, Id extends string = string>(options: {
  readonly subject: Subject<Id> | Id
  readonly attributes: A & WithoutServices<A>
  readonly actor?: Subject | string | undefined
  readonly limit?: Iterable<string> | undefined
  readonly revision?: string | undefined
}): Authenticated<Attributes<A>, IdOf<Id>> => ({
  _tag: "Authenticated",
  subject: toSubject(options.subject as Subject<IdOf<Id>> | IdOf<Id>),
  attributes: cacheEffects(options.attributes),
  actor: options.actor === undefined ? undefined : toSubject(options.actor),
  limits: options.limit === undefined ? [] : [Array.from(options.limit)],
  revision: options.revision
})

/**
 * The anonymous principal.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const guest: Guest = { _tag: "Guest" }

/**
 * Creates a system principal for work the application does on its own
 * authority. The name identifies the job in decision logs.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const system = (name: string): System => ({ _tag: "System", name })

/**
 * Returns `true` when a principal is authenticated.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const isAuthenticated = <A, Id extends string>(self: Principal<A, Id>): self is Authenticated<A, Id> =>
  self._tag === "Authenticated"

/**
 * Returns `true` when a principal is a guest.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const isGuest = <A, Id extends string>(self: Principal<A, Id>): self is Guest => self._tag === "Guest"

/**
 * Returns `true` when a principal is the system.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const isSystem = <A, Id extends string>(self: Principal<A, Id>): self is System => self._tag === "System"

/**
 * Adds a limit to an authenticated principal. Limits only narrow: the request
 * may use an action only if every limit includes it.
 *
 * @stability experimental
 * @category combinators
 * @since 4.1.3
 */
export const withLimit: {
  (limit: Iterable<string>): <A, Id extends string>(self: Authenticated<A, Id>) => Authenticated<A, Id>
  <A, Id extends string>(self: Authenticated<A, Id>, limit: Iterable<string>): Authenticated<A, Id>
} = dual(2, <A, Id extends string>(self: Authenticated<A, Id>, limit: Iterable<string>): Authenticated<A, Id> => ({
  ...self,
  limits: [...self.limits, Array.from(limit)]
}))

/**
 * Records that someone else is acting on the principal's behalf.
 *
 * @stability experimental
 * @category combinators
 * @since 4.1.3
 */
export const withActor: {
  (actor: Subject | string): <A, Id extends string>(self: Authenticated<A, Id>) => Authenticated<A, Id>
  <A, Id extends string>(self: Authenticated<A, Id>, actor: Subject | string): Authenticated<A, Id>
} = dual(2, <A, Id extends string>(self: Authenticated<A, Id>, actor: Subject | string): Authenticated<A, Id> => ({
  ...self,
  actor: toSubject(actor)
}))
