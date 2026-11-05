/**
 * The service that makes permission decisions.
 *
 * `Authorizer` is the swap point of the permission modules: {@link layer}
 * evaluates an application's rules in process, and an adapter for a remote
 * engine is just another layer for the same service. Handlers never call it
 * directly; they go through the typed object built by `Permission.make`.
 *
 * A decision is {@link Allow} or {@link Deny}. Failing to decide, for example
 * because a relation lookup failed, is a `PermissionUnavailable` failure and
 * never an allow or a deny.
 *
 * @stability experimental
 * @since 4.1.3
 */
import * as Context from "../Context.ts"
import * as Effect from "../Effect.ts"
import * as Layer from "../Layer.ts"
import * as Condition from "./Condition.ts"
import type * as Permission from "./Permission.ts"
import * as PermissionError from "./PermissionError.ts"
import type * as Principal from "./Principal.ts"

/**
 * An allowed request. For plans, `condition` is what a resource must satisfy;
 * for checks on a single resource it is always `Condition.always`.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Allow {
  readonly _tag: "Allow"
  readonly action: string
  readonly condition: Condition.Condition<any>
}

/**
 * Why a request was denied: a signed-in caller's reason, or `Unauthenticated`
 * when the caller is a guest.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type DenyReason = PermissionError.DenyReason | "Unauthenticated"

/**
 * A denied request, with the reason.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Deny {
  readonly _tag: "Deny"
  readonly action: string
  readonly reason: DenyReason
}

/**
 * The outcome of a permission check.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Decision = Allow | Deny

/**
 * Creates an {@link Allow} decision.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const allow = (action: string, condition: Condition.Condition<any> = Condition.always): Decision => ({
  _tag: "Allow",
  action,
  condition
})

/**
 * Creates a {@link Deny} decision.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const deny = (action: string, reason: DenyReason): Decision => ({
  _tag: "Deny",
  action,
  reason
})

/**
 * Returns `true` when a decision allows the request.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const isAllow = (self: Decision): self is Allow => self._tag === "Allow"

/**
 * Converts a denial into the error to fail with: `Unauthenticated` (401) for
 * guests, `PermissionDenied` (403) otherwise.
 *
 * @stability experimental
 * @category conversions
 * @since 4.1.3
 */
export const toError = (self: Deny): PermissionError.Unauthenticated | PermissionError.PermissionDenied =>
  self.reason === "Unauthenticated"
    ? new PermissionError.Unauthenticated({ action: self.action })
    : new PermissionError.PermissionDenied({ action: self.action, reason: self.reason })

/**
 * A request to check one resource.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Request {
  readonly principal: Principal.Principal<unknown>
  readonly action: string
  readonly resource: unknown
}

/**
 * The permission decision service.
 *
 * **Details**
 *
 * - `check` decides whether the principal may perform the action on an
 *   existing resource, using the action's `filter` and `forbid` rules.
 * - `checkWrite` decides whether a resource may be written as given, using the
 *   action's `check` rule (or its `filter` when it has no `check`) and its
 *   `forbid` rule.
 * - `plan` decides which resources the principal may perform the action on,
 *   using the action's `filter`, or its `check` for create actions. An allowed
 *   plan's condition refers only to resource fields.
 *
 * @stability experimental
 * @category services
 * @since 4.1.3
 */
export class Authorizer extends Context.Service<
  Authorizer,
  {
    readonly check: (request: Request) => Effect.Effect<Decision, PermissionError.PermissionUnavailable>
    readonly checkWrite: (request: Request) => Effect.Effect<Decision, PermissionError.PermissionUnavailable>
    readonly plan: (request: {
      readonly principal: Principal.Principal<unknown>
      readonly action: string
    }) => Effect.Effect<Decision, PermissionError.PermissionUnavailable>
  }
>()("effect/permission/Authorizer") {}

// -----------------------------------------------------------------------------
// Relations
// -----------------------------------------------------------------------------

/**
 * Answers relation lookups for {@link layer}.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface RelationStore {
  readonly has: (
    relation: Condition.Relation<any, any>,
    subject: unknown,
    object: unknown
  ) => Effect.Effect<boolean, PermissionError.PermissionUnavailable>
}

/**
 * The relation store used by {@link layer}.
 *
 * **Gotchas**
 *
 * Without a store, every relation lookup fails with `PermissionUnavailable`.
 * Provide one with {@link layerRelationsMemory} or `PermissionSql.layer`.
 *
 * @stability experimental
 * @category services
 * @since 4.1.3
 */
export const Relations: Context.Reference<RelationStore> = Context.Reference<RelationStore>(
  "effect/permission/Authorizer/Relations",
  {
    defaultValue: () => ({
      has: (relation) =>
        Effect.logWarning(`No relation store is provided, so "${relation.name}" cannot be checked`).pipe(
          Effect.andThen(Effect.fail(new PermissionError.PermissionUnavailable()))
        )
    })
  }
)

/**
 * Provides a relation store that holds a fixed set of facts in memory, for
 * tests and small applications.
 *
 * @stability experimental
 * @category layers
 * @since 4.1.3
 */
export const layerRelationsMemory = (tuples: Iterable<Condition.RelationTuple>): Layer.Layer<never> => {
  const facts = new Map<Condition.Relation<any, any>, Map<unknown, Set<unknown>>>()
  for (const tuple of tuples) {
    let subjects = facts.get(tuple.relation)
    if (subjects === undefined) {
      subjects = new Map()
      facts.set(tuple.relation, subjects)
    }
    let objects = subjects.get(tuple.subject)
    if (objects === undefined) {
      objects = new Set()
      subjects.set(tuple.subject, objects)
    }
    objects.add(tuple.object)
  }
  return Layer.succeed(Relations, {
    has: (relation, subject, object) => Effect.succeed(facts.get(relation)?.get(subject)?.has(object) ?? false)
  })
}

// -----------------------------------------------------------------------------
// In-process authorizer
// -----------------------------------------------------------------------------

const expand = (
  groups: ReadonlyMap<string, ReadonlyArray<string>>,
  names: ReadonlyArray<string>
): ReadonlySet<string> => {
  const out = new Set<string>()
  const visit = (name: string) => {
    if (out.has(name)) return
    out.add(name)
    for (const member of groups.get(name) ?? []) visit(member)
  }
  names.forEach(visit)
  return out
}

/**
 * Creates an authorizer that evaluates the rules of a `Permission.make`
 * object in process.
 *
 * **Details**
 *
 * - Guests are denied and system principals are allowed every action.
 * - Each of the principal's limits is expanded through the aliases and must
 *   include the action.
 * - `forbid` overrides `filter` and `check`.
 * - Every decision is recorded on the current span as `permission.action`,
 *   `permission.decision`, and `permission.reason`.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const make = <I, A, U extends Permission.Any>(
  permissions: Permission.Permissions<I, A, U>
): Effect.Effect<Authorizer["Service"], never, Permission.ServicesOf<U>> =>
  Effect.gen(function*() {
    const context = yield* Effect.context<Permission.ServicesOf<U>>()
    const relations = yield* Relations

    const evaluate = (condition: Condition.Condition<any>, principal: unknown, resource: unknown) =>
      Condition.evaluate(condition, { principal, resource, related: relations.has }).pipe(
        Effect.catchTag("CustomConditionError", (error) =>
          Effect.logWarning(`Custom condition "${error.name}" failed`, error.cause).pipe(
            Effect.andThen(Effect.fail(new PermissionError.PermissionUnavailable()))
          )),
        Effect.provideContext(context)
      ) as Effect.Effect<boolean, PermissionError.PermissionUnavailable>

    const precheck = (
      principal: Principal.Principal<unknown>,
      action: string
    ): Decision | Permission.Action => {
      switch (principal._tag) {
        case "Guest":
          return deny(action, "Unauthenticated")
        case "System":
          return allow(action)
      }
      const entry = permissions.actions.get(action)
      if (entry === undefined) {
        return deny(action, "NoPermission")
      }
      for (const limit of principal.limits) {
        if (!expand(permissions.aliases, limit).has(action)) {
          return deny(action, "Limit")
        }
      }
      return entry
    }

    const decide = (
      request: Request,
      phase: "read" | "write"
    ): Effect.Effect<Decision, PermissionError.PermissionUnavailable> =>
      Effect.gen(function*() {
        const entry = precheck(request.principal, request.action)
        if ("_tag" in entry) {
          return entry
        }
        const condition = phase === "read" ? entry.filter : entry.check ?? entry.filter
        if (condition === undefined) {
          return deny(request.action, "NoPermission")
        }
        if (entry.forbid !== undefined && (yield* evaluate(entry.forbid, request.principal, request.resource))) {
          return deny(request.action, "Forbidden")
        }
        return (yield* evaluate(condition, request.principal, request.resource))
          ? allow(request.action)
          : deny(request.action, "NoPermission")
      })

    const plan = (request: {
      readonly principal: Principal.Principal<unknown>
      readonly action: string
    }): Effect.Effect<Decision, PermissionError.PermissionUnavailable> =>
      Effect.gen(function*() {
        const entry = precheck(request.principal, request.action)
        if ("_tag" in entry) {
          return entry
        }
        // Create actions have no filter; their check says which resources the
        // principal could create
        const condition = entry.kind === "create" ? entry.check : entry.filter
        if (condition === undefined) {
          return deny(request.action, "NoPermission")
        }
        const residual = yield* Condition.simplify(
          entry.forbid === undefined ? condition : Condition.and(condition, Condition.not(entry.forbid)),
          request.principal
        )
        if (!Condition.isNever(residual)) {
          return allow(request.action, residual)
        }
        const forbidden = entry.forbid !== undefined &&
          Condition.isAlways(yield* Condition.simplify(entry.forbid, request.principal))
        return deny(request.action, forbidden ? "Forbidden" : "NoPermission")
      })

    const record = <E>(effect: Effect.Effect<Decision, E>, name: string, action: string) =>
      effect.pipe(
        Effect.tap((decision) =>
          Effect.annotateCurrentSpan({
            "permission.decision": decision._tag,
            "permission.reason": decision._tag === "Deny" ? decision.reason : undefined
          })
        ),
        Effect.withSpan(name, { attributes: { "permission.action": action } })
      )

    return Authorizer.of({
      check: (request) =>
        record(decide(request, "read"), "Authorizer.check", request.action),
      checkWrite: (request) =>
        record(decide(request, "write"), "Authorizer.checkWrite", request.action),
      plan: (request) => record(plan(request), "Authorizer.plan", request.action)
    })
  })

/**
 * Provides an authorizer that evaluates the rules of a `Permission.make`
 * object in process. `Permissions.layer` is a shorthand for this.
 *
 * @stability experimental
 * @category layers
 * @since 4.1.3
 */
export const layer = <I, A, U extends Permission.Any>(
  permissions: Permission.Permissions<I, A, U>
): Layer.Layer<Authorizer, never, Permission.ServicesOf<U>> => Layer.effect(Authorizer, make(permissions))

/**
 * Provides an authorizer that denies every request.
 *
 * @stability experimental
 * @category layers
 * @since 4.1.3
 */
export const layerDenyAll: Layer.Layer<Authorizer> = Layer.succeed(Authorizer, {
  check: (request) => Effect.succeed(deny(request.action, "NoPermission")),
  checkWrite: (request) => Effect.succeed(deny(request.action, "NoPermission")),
  plan: (request) => Effect.succeed(deny(request.action, "NoPermission"))
})

/**
 * Provides an authorizer that allows every request.
 *
 * **Gotchas**
 *
 * Only for tests and prototypes. Nothing is checked.
 *
 * @stability experimental
 * @category layers
 * @since 4.1.3
 */
export const layerUnsafeAllowAll: Layer.Layer<Authorizer> = Layer.succeed(Authorizer, {
  check: (request) => Effect.succeed(allow(request.action)),
  checkWrite: (request) => Effect.succeed(allow(request.action)),
  plan: (request) => Effect.succeed(allow(request.action))
})
