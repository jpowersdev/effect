/**
 * Permission rules, and the typed object handlers use to enforce them.
 *
 * {@link rules} declares what each action requires on one resource type.
 * {@link make} combines rule sets into the application's `Permissions` object,
 * whose methods check the principal provided by the application:
 *
 * - `can` returns a decision without failing, for UI affordances.
 * - `require` fails unless the action is allowed, with `Unauthenticated` for
 *   guests and `PermissionDenied` otherwise, and returns the resource branded
 *   as {@link Authorized}.
 * - `filter` returns the condition a resource must satisfy, for list queries.
 * - `create` and `update` apply `set` presets and check the written value.
 * - `Required` is the annotation key that the HttpApi and RPC middleware read.
 *
 * **Example** (Requiring a permission)
 *
 * ```ts
 * import { Context, Effect, Schema } from "effect"
 * import { Condition, Permission, Principal } from "effect/permission"
 *
 * class Document extends Schema.Class<Document>("Document")({
 *   id: Schema.String,
 *   ownerId: Schema.String
 * }) {}
 *
 * class CurrentPrincipal extends Context.Service<
 *   CurrentPrincipal,
 *   Principal.Principal<{ readonly admin: boolean }>
 * >()("app/CurrentPrincipal") {}
 *
 * const DocumentRules = Permission.rules(CurrentPrincipal, Document, {
 *   "documents:read": {
 *     filter: ({ principal, resource }) =>
 *       Condition.or(principal.attributes.admin, Condition.eq(resource.ownerId, principal.subject.id))
 *   }
 * })
 *
 * const Permissions = Permission.make(CurrentPrincipal, { rules: [DocumentRules] })
 *
 * const program = Permissions.require("documents:read", new Document({ id: "d1", ownerId: "u1" })).pipe(
 *   Effect.provideService(CurrentPrincipal, Principal.make({ subject: "u1", attributes: { admin: false } })),
 *   Effect.provide(Permissions.layer)
 * )
 * ```
 *
 * @stability experimental
 * @since 4.1.3
 */
import * as Context from "../Context.ts"
import * as Effect from "../Effect.ts"
import type * as Layer from "../Layer.ts"
import type * as Schema from "../Schema.ts"
import type * as Types from "../Types.ts"
import * as Authorizer from "./Authorizer.ts"
import * as Condition from "./Condition.ts"
import type * as PermissionError from "./PermissionError.ts"
import type * as Principal from "./Principal.ts"

const RulesTypeId = "~effect/permission/Permission/Rules" as const
const PermissionsTypeId = "~effect/permission/Permission" as const
const AuthorizedTypeId = "~effect/permission/Permission/Authorized" as const

/**
 * Marks an endpoint or RPC as needing no permission, so the authorization
 * middleware lets it through.
 *
 * **Example** (Marking a health check public)
 *
 * ```ts
 * import { Context, Schema } from "effect"
 * import { HttpApiEndpoint } from "effect/http-api"
 * import { Permission, type Principal } from "effect/permission"
 *
 * class CurrentPrincipal extends Context.Service<CurrentPrincipal, Principal.Principal<{}>>()("app/CurrentPrincipal") {}
 * const Permissions = Permission.make(CurrentPrincipal, { rules: [] })
 *
 * const health = HttpApiEndpoint.get("health", "/health", { success: Schema.String })
 *   .annotate(Permissions.Required, Permission.Public)
 * ```
 *
 * @stability experimental
 * @category annotations
 * @since 4.1.3
 */
export const Public: unique symbol = Symbol.for("effect/permission/Permission/Public")

/**
 * The type of {@link Public}.
 *
 * @stability experimental
 * @category annotations
 * @since 4.1.3
 */
export type Public = typeof Public

// -----------------------------------------------------------------------------
// Rules
// -----------------------------------------------------------------------------

/**
 * What a rule definition receives: references to the principal's and the
 * resource's fields, and `allowed`, which returns another action's `filter` on
 * the same resource.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Input<A, Resource, Actions extends string> {
  readonly principal: Principal.Refs<A>
  readonly resource: Condition.Refs<Resource>
  readonly allowed: (action: Actions) => Condition.Condition
}

/**
 * The rule for one action on one resource type.
 *
 * **Details**
 *
 * - `filter`: which existing resources the action may touch. Used by
 *   `require`, `can`, `filter`, and on the old value by `update`.
 * - `check`: what a resource must satisfy after a write, checked on the new
 *   value by `create` and `update`. Defaults to `filter`.
 * - `set`: values written for the caller, which override the payload. It
 *   receives the real principal, not references.
 * - `forbid`: when the action is denied regardless of `filter` and `check`.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Definition<A, Resource, Actions extends string> {
  readonly filter?: ((input: Input<A, Resource, Actions>) => Condition.Input<any>) | undefined
  readonly check?: ((input: Input<A, Resource, Actions>) => Condition.Input<any>) | undefined
  readonly forbid?: ((input: Input<A, Resource, Actions>) => Condition.Input<any>) | undefined
  readonly set?: ((input: { readonly principal: Principal.Authenticated<A> }) => Partial<Resource>) | undefined
}

/**
 * One compiled action: its resource schema, its conditions, and its presets.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Action {
  readonly name: string
  readonly resource: Schema.Top
  readonly filter: Condition.Condition<any> | undefined
  readonly check: Condition.Condition<any> | undefined
  readonly forbid: Condition.Condition<any> | undefined
  readonly set: ((input: { readonly principal: Principal.Authenticated<any> }) => object) | undefined
}

/**
 * The rules for one resource type, created by {@link rules}.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Rules<out Resource, out Actions extends string, out R, out Presets> {
  readonly [RulesTypeId]: {
    readonly _Resource: Types.Covariant<Resource>
    readonly _Actions: Types.Covariant<Actions>
    readonly _R: Types.Covariant<R>
    readonly _Presets: Types.Covariant<Presets>
  }
  readonly resource: Schema.Top
  readonly actions: ReadonlyMap<string, Action>
}

/**
 * Any rule set.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Any = Rules<any, any, any, any>

/**
 * The action names declared by a union of rule sets.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type ActionsOf<U> = U extends Rules<any, infer Actions, any, any> ? Actions : never

/**
 * The resource type of an action.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type ResourceOf<U, Action extends string> = U extends Rules<infer Resource, infer Actions, any, any> ?
  [Action] extends [Actions] ? Resource : never
  : never

/**
 * The fields an action's `set` presets fill in.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type PresetsOf<U, Action extends string> = U extends Rules<any, infer Actions, any, infer Presets> ?
  [Action] extends [Actions] ? Action extends keyof Presets ? Presets[Action] : never : never
  : never

/**
 * The services required by custom conditions in a union of rule sets.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type ServicesOf<U> = U extends Rules<any, any, infer R, any> ? R : never

type ConditionOf<F> = F extends (...args: ReadonlyArray<any>) => infer C ? C : never

type DefinitionServices<D> = {
  [K in keyof D]: Condition.Services<
    | ConditionOf<D[K] extends { readonly filter?: infer F } ? F : never>
    | ConditionOf<D[K] extends { readonly check?: infer F } ? F : never>
    | ConditionOf<D[K] extends { readonly forbid?: infer F } ? F : never>
  >
}[keyof D]

type DefinitionPresets<D> = {
  readonly [K in keyof D]: D[K] extends { readonly set?: infer F } ?
    F extends (...args: ReadonlyArray<any>) => infer O ? keyof O : never
    : never
}

const toCondition = (input: Condition.Input<any>): Condition.Condition<any> =>
  Condition.isRef(input) ? Condition.and(input) : input

/**
 * Declares the rules for the actions on one resource type.
 *
 * **Details**
 *
 * Rule functions are called once, when the rules are declared, with
 * references to the principal's and the resource's fields; they record
 * conditions rather than checking values. `set` is the exception: it runs on
 * every `create` and `update` with the real principal.
 *
 * Every action needs a `filter` or a `check`. Referring to an unknown action
 * through `allowed`, or to an action whose `filter` refers back to itself, is
 * a defect when the rules are declared.
 *
 * **Example** (Declaring rules for units)
 *
 * ```ts
 * import { Context, Schema } from "effect"
 * import { Condition, Permission, type Principal } from "effect/permission"
 *
 * class Unit extends Schema.Class<Unit>("Unit")({ id: Schema.String, hospitalId: Schema.String }) {}
 *
 * class CurrentPrincipal extends Context.Service<
 *   CurrentPrincipal,
 *   Principal.Principal<{ readonly hospitalId: string; readonly manager: boolean }>
 * >()("app/CurrentPrincipal") {}
 *
 * const UnitRules = Permission.rules(CurrentPrincipal, Unit, {
 *   "units:read": {
 *     filter: ({ principal, resource: unit }) => Condition.eq(unit.hospitalId, principal.attributes.hospitalId)
 *   },
 *   "units:update": {
 *     filter: ({ principal, allowed }) => Condition.and(allowed("units:read"), principal.attributes.manager),
 *     check: ({ allowed }) => allowed("units:read")
 *   }
 * })
 * ```
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const rules = <
  I,
  A,
  S extends Schema.Top,
  const D extends Readonly<Record<string, Definition<A, S["Type"], string>>>
>(
  _principal: Context.Key<I, Principal.Principal<A>>,
  resource: S,
  definitions: D
): Rules<S["Type"], keyof D & string, DefinitionServices<D>, DefinitionPresets<D>> => {
  const refs = Condition.refs<Principal.Fields<A>, S["Type"]>()
  const filters = new Map<string, Condition.Condition<any>>()
  const pending = new Set<string>()
  const defs = definitions as Record<string, Definition<A, S["Type"], string>>

  const filterOf = (name: string): Condition.Condition<any> => {
    const cached = filters.get(name)
    if (cached !== undefined) return cached
    const definition = defs[name]
    if (definition === undefined) throw new Error(`Permission.rules: unknown action "${name}"`)
    if (definition.filter === undefined) throw new Error(`Permission.rules: "${name}" has no filter`)
    if (pending.has(name)) throw new Error(`Permission.rules: "${name}" refers to itself through allowed`)
    pending.add(name)
    const condition = toCondition(definition.filter(input))
    pending.delete(name)
    filters.set(name, condition)
    return condition
  }
  const input: Input<A, S["Type"], string> = { ...refs, allowed: filterOf as (name: string) => Condition.Condition }

  const actions = new Map<string, Action>()
  for (const [name, definition] of Object.entries(defs)) {
    if (definition.filter === undefined && definition.check === undefined) {
      throw new Error(`Permission.rules: "${name}" needs a filter or a check`)
    }
    actions.set(name, {
      name,
      resource,
      filter: definition.filter === undefined ? undefined : filterOf(name),
      check: definition.check === undefined ? undefined : toCondition(definition.check(input)),
      forbid: definition.forbid === undefined ? undefined : toCondition(definition.forbid(input)),
      set: definition.set as Action["set"]
    })
  }
  return { [RulesTypeId]: rulesVariance, resource, actions } as any
}

const rulesVariance = {
  _Resource: (_: never) => _,
  _Actions: (_: never) => _,
  _R: (_: never) => _,
  _Presets: (_: never) => _
}

// -----------------------------------------------------------------------------
// Permissions
// -----------------------------------------------------------------------------

/**
 * A resource that passed a permission check for an action.
 *
 * **When to use**
 *
 * Use to type functions that must only run after a check, such as a
 * repository method that approves a request.
 *
 * **Gotchas**
 *
 * The brand exists only in types. Values are not copied or marked at runtime.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Authorized<Action extends string, A> = A & {
  readonly [AuthorizedTypeId]: { readonly [K in Action]: true }
}

/**
 * The typed object created by {@link make}.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Permissions<I, A, U extends Any> {
  readonly [PermissionsTypeId]: typeof PermissionsTypeId
  /**
   * The application's principal service.
   */
  readonly principal: Context.Key<I, Principal.Principal<A>>
  /**
   * The annotation key for the action an endpoint or RPC requires, or
   * {@link Public}.
   */
  readonly Required: Context.Reference<ActionsOf<U> | Public | undefined>
  /**
   * Every action, by name.
   */
  readonly actions: ReadonlyMap<string, Action>
  /**
   * The actions each alias stands for, by alias.
   */
  readonly aliases: ReadonlyMap<string, ReadonlyArray<string>>
  /**
   * An in-process authorizer for these rules.
   */
  readonly layer: Layer.Layer<Authorizer.Authorizer, never, ServicesOf<U>>
  /**
   * Decides whether the principal may perform the action on the resource,
   * without failing on a deny.
   */
  can<Ac extends ActionsOf<U>>(
    action: Ac,
    resource: ResourceOf<U, Ac>
  ): Effect.Effect<Authorizer.Decision, PermissionError.PermissionUnavailable, I | Authorizer.Authorizer>
  /**
   * Fails unless the principal may perform the action on the resource:
   * `Unauthenticated` for guests, `PermissionDenied` otherwise.
   */
  require<Ac extends ActionsOf<U>, Resource extends ResourceOf<U, Ac>>(
    action: Ac,
    resource: Resource
  ): Effect.Effect<Authorized<Ac, Resource>, PermissionError.PermissionError, I | Authorizer.Authorizer>
  /**
   * Returns the condition a resource must satisfy for the principal to perform
   * the action, with the principal's values filled in. A denied plan returns
   * `Condition.never`.
   */
  filter<Ac extends ActionsOf<U>>(
    action: Ac
  ): Effect.Effect<Condition.Condition<ServicesOf<U>>, PermissionError.PermissionUnavailable, I | Authorizer.Authorizer>
  /**
   * Applies the action's `set` presets to a payload, then checks the result.
   */
  create<Ac extends ActionsOf<U>, Payload extends object>(
    action: Ac,
    payload: Payload
  ): Effect.Effect<
    Authorized<Ac, Payload & Pick<ResourceOf<U, Ac>, PresetsOf<U, Ac> & keyof ResourceOf<U, Ac>>>,
    PermissionError.PermissionError,
    I | Authorizer.Authorizer
  >
  /**
   * Checks the resource as it is, applies the patch and the action's `set`
   * presets, then checks the resource as it would be.
   */
  update<Ac extends ActionsOf<U>, Resource extends ResourceOf<U, Ac>>(
    action: Ac,
    resource: Resource,
    patch: Partial<Omit<ResourceOf<U, Ac>, PresetsOf<U, Ac>>>
  ): Effect.Effect<Authorized<Ac, Resource>, PermissionError.PermissionError, I | Authorizer.Authorizer>
}

const merge = (base: object, ...parts: ReadonlyArray<object>): any =>
  Object.assign(Object.create(Object.getPrototypeOf(base)), base, ...parts)

/**
 * Combines rule sets into the application's typed `Permissions` object.
 *
 * **Details**
 *
 * `aliases` names lists of actions for principal limits: if a limit includes
 * an alias, it includes every action the alias stands for. Aliases may stand
 * for other aliases.
 *
 * Declaring the same action in two rule sets is a defect.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const make = <I, A, const Rs extends ReadonlyArray<Any>>(
  principal: Context.Key<I, Principal.Principal<A>>,
  options: {
    readonly rules: Rs
    readonly aliases?: Readonly<Record<string, ReadonlyArray<string>>> | undefined
  }
): Permissions<I, A, Rs[number]> => {
  const actions = new Map<string, Action>()
  for (const ruleSet of options.rules) {
    for (const [name, action] of ruleSet.actions) {
      if (actions.has(name)) throw new Error(`Permission.make: "${name}" is declared twice`)
      actions.set(name, action)
    }
  }
  const aliases = new Map(Object.entries(options.aliases ?? {}))

  const decide = Effect.fnUntraced(function*(method: "check" | "checkWrite", action: string, resource: unknown) {
    const authorizer = yield* Authorizer.Authorizer
    return yield* authorizer[method]({ principal: yield* principal, action, resource })
  })

  const orDeny = (decision: Authorizer.Decision) =>
    decision._tag === "Deny" ? Effect.fail(Authorizer.toError(decision)) : Effect.void

  const presets = (name: string, current: Principal.Principal<A>): object => {
    const set = actions.get(name)?.set
    if (set === undefined || current._tag !== "Authenticated") return {}
    return set({ principal: current })
  }

  const self: Permissions<I, A, Rs[number]> = {
    [PermissionsTypeId]: PermissionsTypeId,
    principal,
    Required: Context.Reference<any>(`${principal.key}/Required`, { defaultValue: () => undefined }),
    actions,
    aliases,
    get layer() {
      return Authorizer.layer(self)
    },
    can: (action, resource) => decide("check", action, resource),
    require: (action, resource) =>
      decide("check", action, resource).pipe(
        Effect.flatMap(orDeny),
        Effect.as(resource as any)
      ),
    filter: Effect.fnUntraced(function*(action: string) {
      const authorizer = yield* Authorizer.Authorizer
      const decision = yield* authorizer.plan({ principal: yield* principal, action })
      return decision._tag === "Allow" ? decision.condition : Condition.never
    }),
    create: Effect.fnUntraced(function*(action: string, payload: object) {
      const value = { ...payload, ...presets(action, yield* principal) }
      yield* orDeny(yield* decide("checkWrite", action, value))
      return value as any
    }),
    update: Effect.fnUntraced(function*(action: string, resource: object, patch: object) {
      yield* orDeny(yield* decide("check", action, resource))
      const value = merge(resource, patch, presets(action, yield* principal))
      yield* orDeny(yield* decide("checkWrite", action, value))
      return value
    })
  }
  return self
}
