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
 * attribute type is theirs and handlers that check permissions require it.
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
import { dual } from "../Function.ts"
import type * as Condition from "./Condition.ts"

/**
 * Who a principal is: a user or a service, identified by an id.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Subject {
  readonly kind: "user" | "service"
  readonly id: string
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
export interface Authenticated<out A> {
  readonly _tag: "Authenticated"
  readonly subject: Subject
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
export type Principal<A> = Authenticated<A> | Guest | System

/**
 * The fields of an authenticated principal that rules can reference.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Fields<A> {
  readonly subject: Subject
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
export type Refs<A> = Condition.Refs<Fields<A>>

const toSubject = (subject: Subject | string): Subject =>
  typeof subject === "string" ? { kind: "user", id: subject } : subject

/**
 * Creates an authenticated principal. A string subject is a user id.
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
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const make = <A>(options: {
  readonly subject: Subject | string
  readonly attributes: A
  readonly actor?: Subject | string | undefined
  readonly limit?: Iterable<string> | undefined
  readonly revision?: string | undefined
}): Authenticated<A> => ({
  _tag: "Authenticated",
  subject: toSubject(options.subject),
  attributes: options.attributes,
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
export const isAuthenticated = <A>(self: Principal<A>): self is Authenticated<A> => self._tag === "Authenticated"

/**
 * Returns `true` when a principal is a guest.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const isGuest = <A>(self: Principal<A>): self is Guest => self._tag === "Guest"

/**
 * Returns `true` when a principal is the system.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const isSystem = <A>(self: Principal<A>): self is System => self._tag === "System"

/**
 * Adds a limit to an authenticated principal. Limits only narrow: the request
 * may use an action only if every limit includes it.
 *
 * @stability experimental
 * @category combinators
 * @since 4.1.3
 */
export const withLimit: {
  (limit: Iterable<string>): <A>(self: Authenticated<A>) => Authenticated<A>
  <A>(self: Authenticated<A>, limit: Iterable<string>): Authenticated<A>
} = dual(2, <A>(self: Authenticated<A>, limit: Iterable<string>): Authenticated<A> => ({
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
  (actor: Subject | string): <A>(self: Authenticated<A>) => Authenticated<A>
  <A>(self: Authenticated<A>, actor: Subject | string): Authenticated<A>
} = dual(2, <A>(self: Authenticated<A>, actor: Subject | string): Authenticated<A> => ({
  ...self,
  actor: toSubject(actor)
}))
