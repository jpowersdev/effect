/**
 * Permission rules, and the typed object handlers use to enforce them.
 *
 * {@link rules} starts the rules for one resource type. Its `action` method
 * declares an action on existing resources, and its `create` method declares
 * an action that creates them. {@link make} combines rule sets into the
 * application's `Permissions` object, whose methods check the principal
 * provided by the application:
 *
 * - `can` returns a decision without failing, for UI affordances.
 * - `require` fails unless the action is allowed, with `Unauthenticated` for
 *   guests and `PermissionDenied` otherwise, and returns the resource branded
 *   as {@link Authorized}.
 * - `filter` returns the condition a resource must satisfy, for list queries.
 * - `create` builds the value a create action writes, from the payload and the
 *   action's `set` presets, then checks it.
 * - `update` builds the value an update writes, from the resource, a patch,
 *   and the action's `set` presets, checking the resource before and after.
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
 * const DocumentRules = Permission.rules(CurrentPrincipal, Document)
 *   .action("documents:read", {
 *     filter: ({ principal, resource }) =>
 *       Condition.or(principal.attributes.admin, Condition.eq(resource.ownerId, principal.subject.id))
 *   })
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
import { type Pipeable, pipeArguments } from "../Pipeable.ts"
import * as Predicate from "../Predicate.ts"
import type * as Schema from "../Schema.ts"
import type * as Model from "../schema/Model.ts"
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
// Create schemas
// -----------------------------------------------------------------------------

type MakeIn<S extends Schema.Top> = S["~type.make.in"]

type RequiredKeys<A> = { [K in keyof A]-?: {} extends Pick<A, K> ? never : K }[keyof A]

/**
 * The schema `create` builds a resource with: the `insert` variant of a
 * `Model` class, or the resource schema itself.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type CreateSchema<S extends Schema.Top> = S extends Model.Any ? S["insert"] : S

/**
 * What a caller provides to create a resource: the `jsonCreate` variant of a
 * `Model` class, or the constructor input of the resource schema.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type CreatePayload<S extends Schema.Top> = S extends Model.Any ? S["jsonCreate"]["Type"] : MakeIn<S>

/**
 * The fields a create action's `set` must fill: the ones {@link CreateSchema}
 * requires that {@link CreatePayload} doesn't provide.
 *
 * **Details**
 *
 * Fields with a constructor default, such as `Model.UuidV4Insert` and
 * `Model.DateTimeInsert`, are not required. For a resource schema that isn't a
 * `Model` class, the payload provides every field, so `set` is optional.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type RequiredPresets<S extends Schema.Top> = Pick<
  MakeIn<CreateSchema<S>>,
  Exclude<RequiredKeys<MakeIn<CreateSchema<S>>>, keyof CreatePayload<S>>
>

/**
 * The schema `update` builds a resource with: the `update` variant of a
 * `Model` class, or the resource schema itself.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type UpdateSchema<S extends Schema.Top> = S extends Model.Any ? S["update"] : S

/**
 * What a caller provides to update a resource: the `jsonUpdate` variant of a
 * `Model` class, or the constructor input of the resource schema. `update`
 * takes any part of it.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type UpdatePayload<S extends Schema.Top> = S extends Model.Any ? S["jsonUpdate"]["Type"] : MakeIn<S>

// Matches `Model.Any`, which is structural
const isModel = (resource: Schema.Top): resource is Schema.Top & Model.Any =>
  Predicate.hasProperty(resource, "insert") && Predicate.hasProperty(resource, "jsonCreate")

const createSchema = (resource: Schema.Top): Schema.Top => isModel(resource) ? resource.insert : resource

const updateSchema = (resource: Schema.Top): Schema.Top => isModel(resource) ? resource.update : resource

const fieldsOf = (variant: Schema.Top): Schema.Struct.Fields => (variant as Schema.Struct<Schema.Struct.Fields>).fields

// The fields of the resource that carry over into an update. A `Model` class
// carries its `update` fields, except the ones that variant generates and a
// payload can't set, such as `Model.DateTimeUpdate`.
const carried = (resource: Schema.Top, row: object): object => {
  if (!isModel(resource)) return { ...row }
  const fields = fieldsOf(resource.update)
  const payload = fieldsOf(resource.jsonUpdate)
  const out: Record<string, unknown> = {}
  for (const key of Object.keys(fields)) {
    if (fields[key].ast.context?.constructorDefault !== undefined && !(key in payload)) continue
    if (key in row) out[key] = (row as Record<string, unknown>)[key]
  }
  return out
}

// -----------------------------------------------------------------------------
// Type-level errors
// -----------------------------------------------------------------------------

/**
 * The parameter type of a rule set's `action` and `create` methods when the
 * action name is already declared, so the error names the action.
 *
 * @stability experimental
 * @category type-level errors
 * @since 4.1.3
 */
export interface AlreadyDeclared<Action extends string> {
  readonly "is already declared": Action
}

/**
 * The parameter type of `Permissions.create` when the action is not declared
 * with `create`, so the error names the action.
 *
 * @stability experimental
 * @category type-level errors
 * @since 4.1.3
 */
export interface NotACreateAction<Action extends string> {
  readonly "is not a create action": Action
}

/**
 * The parameter type of `Permissions.can`, `require`, and `update` when the
 * action is declared with `create`, so the error names the action.
 *
 * @stability experimental
 * @category type-level errors
 * @since 4.1.3
 */
export interface IsACreateAction<Action extends string> {
  readonly "is a create action": Action
}

// -----------------------------------------------------------------------------
// Rules
// -----------------------------------------------------------------------------

/**
 * What a create rule receives: references to the principal's and the
 * resource's fields.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Input<A, Id extends string, Resource> {
  readonly principal: Principal.Refs<A, Id>
  readonly resource: Condition.Refs<Resource>
}

/**
 * What a rule on existing resources receives: {@link Input}, and `allowed`,
 * which returns the `filter` of an action declared before it on the same
 * resource.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface ActionInput<A, Id extends string, Resource, Allowed extends string> extends Input<A, Id, Resource> {
  readonly allowed: (action: Allowed) => Condition.Condition
}

/**
 * What `set` returns: the values, or an effect that computes them, for a `set`
 * that reads a `Principal.Lazy` attribute.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Presets<A> = A | Effect.Effect<A, PermissionError.PermissionUnavailable>

/**
 * What `set` receives: the real principal, not references.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface SetInput<A, Id extends string> {
  readonly principal: Principal.Authenticated<A, Id>
}

/**
 * The rule for an action on existing resources.
 *
 * **Details**
 *
 * - `filter`: which existing resources the action may touch. Used by
 *   `require`, `can`, `filter`, and on the old value by `update`.
 * - `check`: what a resource must satisfy after `update`, with the update
 *   applied. Defaults to `filter`.
 * - `set`: values `update` writes for a signed-in principal, which override
 *   the patch. They are fields of the value {@link UpdateSchema} builds. The
 *   system principal gets no `set`, so it passes them in the patch. A `set`
 *   that reads a `Principal.Lazy` attribute returns an effect.
 * - `forbid`: when the action is denied regardless of `filter` and `check`.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface ActionOptions<A, Id extends string, S extends Schema.Top, Allowed extends string> {
  readonly filter: (input: ActionInput<A, Id, S["Type"], Allowed>) => Condition.Input<any>
  readonly check?: ((input: ActionInput<A, Id, S["Type"], Allowed>) => Condition.Input<any>) | undefined
  readonly forbid?: ((input: ActionInput<A, Id, S["Type"], Allowed>) => Condition.Input<any>) | undefined
  readonly set?: ((input: SetInput<A, Id>) => Presets<Partial<MakeIn<UpdateSchema<S>>>>) | undefined
}

/**
 * The rule for an action that creates resources.
 *
 * **Details**
 *
 * - `check`: what the new resource must satisfy. It refers to the value
 *   {@link CreateSchema} builds, so a `Model` field the database generates is
 *   not available.
 * - `set`: values written for a signed-in principal, which override the
 *   payload. It must fill the {@link RequiredPresets}. The system principal
 *   gets no `set`, so it passes them in the payload. A `set` that reads a
 *   `Principal.Lazy` attribute returns an effect.
 * - `forbid`: when the action is denied regardless of `check`.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type CreateOptions<A, Id extends string, S extends Schema.Top> =
  & {
    readonly check: (input: Input<A, Id, CreateSchema<S>["Type"]>) => Condition.Input<any>
    readonly forbid?: ((input: Input<A, Id, CreateSchema<S>["Type"]>) => Condition.Input<any>) | undefined
  }
  & ([keyof RequiredPresets<S>] extends [never] ? {
      readonly set?: ((input: SetInput<A, Id>) => Presets<Partial<MakeIn<CreateSchema<S>>>>) | undefined
    }
    : {
      readonly set: (input: SetInput<A, Id>) => Presets<RequiredPresets<S> & Partial<MakeIn<CreateSchema<S>>>>
    })

/**
 * One compiled action: its kind, its resource schema, its conditions, and its
 * presets.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Action {
  readonly name: string
  readonly kind: "action" | "create"
  readonly resource: Schema.Top
  readonly filter: Condition.Condition<any> | undefined
  readonly check: Condition.Condition<any> | undefined
  readonly forbid: Condition.Condition<any> | undefined
  readonly set: ((input: SetInput<any, any>) => Presets<object>) | undefined
}

type ConditionOf<F> = F extends (...args: ReadonlyArray<any>) => infer C ? C : never

// A rule that doesn't type-check falls back to its options constraint, whose
// conditions require `any`; dropping it keeps the error at the rule instead of
// in every layer built from these rules
type OptionsServices<D> = IgnoreAny<
  Condition.Services<
    | ConditionOf<D extends { readonly filter?: infer F } ? F : never>
    | ConditionOf<D extends { readonly check?: infer F } ? F : never>
    | ConditionOf<D extends { readonly forbid?: infer F } ? F : never>
  >
>

type IgnoreAny<R> = 0 extends 1 & R ? never : R

type OptionsPresets<D> = D extends { readonly set?: infer F } ?
  F extends (...args: ReadonlyArray<any>) => infer O ? keyof (O extends Effect.Effect<infer P, any, any> ? P : O)
  : never
  : never

type AddPresets<Presets, Ac extends string, D> = [OptionsPresets<D>] extends [never] ? Presets
  : Types.Simplify<Presets & { readonly [K in Ac]: OptionsPresets<D> }>

/**
 * The rules for one resource type, created by {@link rules}.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Rules<
  A,
  Id extends string,
  S extends Schema.Top,
  Actions extends string,
  Creates extends string,
  R,
  Presets
> extends Pipeable {
  readonly [RulesTypeId]: {
    readonly _S: Types.Covariant<S>
    readonly _Actions: Types.Covariant<Actions>
    readonly _Creates: Types.Covariant<Creates>
    readonly _R: Types.Covariant<R>
    readonly _Presets: Types.Covariant<Presets>
  }
  readonly resource: S
  readonly actions: ReadonlyMap<string, Action>
  /**
   * Declares an action on existing resources. Every action needs a `filter`;
   * see {@link ActionOptions}.
   */
  action<const Ac extends string, const D extends ActionOptions<A, Id, S, Exclude<Actions, Creates>>>(
    name: Ac extends Actions ? AlreadyDeclared<Ac> : Ac,
    options: D
  ): Rules<A, Id, S, Actions | Ac, Creates, R | OptionsServices<D>, AddPresets<Presets, Ac, D>>
  /**
   * Declares an action that creates resources. Every create action needs a
   * `check`; see {@link CreateOptions}.
   */
  create<const Ac extends string, const D extends CreateOptions<A, Id, S>>(
    name: Ac extends Actions ? AlreadyDeclared<Ac> : Ac,
    options: D
  ): Rules<A, Id, S, Actions | Ac, Creates | Ac, R | OptionsServices<D>, AddPresets<Presets, Ac, D>>
}

/**
 * Any rule set.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Any = Rules<any, any, any, any, any, any, any>

/**
 * The action names declared by a union of rule sets.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type ActionsOf<U> = U extends Rules<any, any, any, infer Actions, any, any, any> ? Actions : never

/**
 * The names of the actions declared with `create` by a union of rule sets.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type CreateActionsOf<U> = U extends Rules<any, any, any, any, infer Creates, any, any> ? Creates : never

/**
 * The resource type of an action.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type ResourceOf<U, Action extends string> = U extends
  Rules<any, any, infer S extends Schema.Top, infer Actions, any, any, any> ?
  [Action] extends [Actions] ? S["Type"] : never
  : never

/**
 * The fields an action's `set` presets fill in.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type PresetsOf<U, Action extends string> = U extends
  Rules<any, any, any, infer Actions, any, any, infer Presets> ?
  [Action] extends [Actions] ? Action extends keyof Presets ? Presets[Action] : never : never
  : never

/**
 * The value `Permissions.create` builds for a create action.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type CreatedOf<U, Action extends string> = U extends
  Rules<any, any, infer S extends Schema.Top, any, infer Creates, any, any> ?
  [Action] extends [Creates] ? CreateSchema<S>["Type"] : never
  : never

/**
 * The payload `Permissions.create` takes for a create action. If the action
 * has a `set`, this is one of two shapes, one per kind of principal:
 * {@link AuthenticatedPayloadOf} for a signed-in principal, whose `set` fills
 * its fields, and {@link SystemPayloadOf} for the system principal, which gets
 * no `set`.
 *
 * **Details**
 *
 * Which principal runs the call is only known at runtime, so both shapes are
 * accepted. If a signed-in principal's payload has the fields `set` fills,
 * `set` replaces them.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type PayloadOf<U, Action extends string> = [PresetsOf<U, Action>] extends [never] ?
  AuthenticatedPayloadOf<U, Action>
  : AuthenticatedPayloadOf<U, Action> | SystemPayloadOf<U, Action>

/**
 * The payload of a create action for a signed-in principal: the
 * {@link CreatePayload}, without the fields the action's `set` fills.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type AuthenticatedPayloadOf<U, Action extends string> = U extends
  Rules<any, any, infer S extends Schema.Top, any, infer Creates, any, any> ?
  [Action] extends [Creates] ? Types.Simplify<
      & Omit<CreatePayload<S>, PresetsOf<U, Action>>
      & { readonly [K in PresetsOf<U, Action>]?: never }
    >
  : never
  : never

/**
 * The payload of a create action for the system principal: the
 * {@link CreatePayload}, with the fields the action's `set` would fill. The
 * system principal gets no `set`, because there's no signed-in user for it to
 * read.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type SystemPayloadOf<U, Action extends string> = U extends
  Rules<any, any, infer S extends Schema.Top, any, infer Creates, any, any> ?
  [Action] extends [Creates] ? Types.Simplify<
      & Omit<CreatePayload<S>, PresetsOf<U, Action>>
      & Pick<MakeIn<CreateSchema<S>>, PresetsOf<U, Action> & keyof MakeIn<CreateSchema<S>>>
    >
  : never
  : never

/**
 * The value `Permissions.update` builds for an action on existing resources.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type UpdatedOf<U, Action extends string> = U extends
  Rules<any, any, infer S extends Schema.Top, infer Actions, any, any, any> ?
  [Action] extends [Actions] ? UpdateSchema<S>["Type"] : never
  : never

/**
 * The patch `Permissions.update` takes for an action. If the action has a
 * `set`, this is one of two shapes, one per kind of principal:
 * {@link AuthenticatedPatchOf} for a signed-in principal, whose `set` fills its
 * fields, and {@link SystemPatchOf} for the system principal, which gets no
 * `set`.
 *
 * **Details**
 *
 * Which principal runs the call is only known at runtime, so both shapes are
 * accepted. If a signed-in principal's patch has the fields `set` fills, `set`
 * replaces them.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type PatchOf<U, Action extends string> = [PresetsOf<U, Action>] extends [never] ? AuthenticatedPatchOf<U, Action>
  : AuthenticatedPatchOf<U, Action> | SystemPatchOf<U, Action>

/**
 * The patch of an action for a signed-in principal: any part of the
 * {@link UpdatePayload}, without the fields the action's `set` fills.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type AuthenticatedPatchOf<U, Action extends string> = U extends
  Rules<any, any, infer S extends Schema.Top, infer Actions, any, any, any> ?
  [Action] extends [Actions] ? Types.Simplify<
      & Partial<Omit<UpdatePayload<S>, PresetsOf<U, Action>>>
      & { readonly [K in PresetsOf<U, Action>]?: never }
    >
  : never
  : never

/**
 * The patch of an action for the system principal: any part of the
 * {@link UpdatePayload}, and of the fields the action's `set` would fill. The
 * system principal gets no `set`, because there's no signed-in user for it to
 * read.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type SystemPatchOf<U, Action extends string> = U extends
  Rules<any, any, infer S extends Schema.Top, infer Actions, any, any, any> ?
  [Action] extends [Actions] ? Types.Simplify<
      Partial<
        & Omit<UpdatePayload<S>, PresetsOf<U, Action>>
        & Pick<MakeIn<UpdateSchema<S>>, PresetsOf<U, Action> & keyof MakeIn<UpdateSchema<S>>>
      >
    >
  : never
  : never

/**
 * The services required by custom conditions in a union of rule sets.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type ServicesOf<U> = U extends Rules<any, any, any, any, any, infer R, any> ? R : never

const toCondition = (input: Condition.Input<any>): Condition.Condition<any> =>
  Condition.isRef(input) ? Condition.and(input) : input

type AnyOptions = {
  readonly filter?: ((input: any) => Condition.Input<any>) | undefined
  readonly check?: ((input: any) => Condition.Input<any>) | undefined
  readonly forbid?: ((input: any) => Condition.Input<any>) | undefined
  readonly set?: ((input: SetInput<any, any>) => Presets<object>) | undefined
}

const declare = (self: Any, name: string, kind: Action["kind"], options: AnyOptions): Any => {
  if (self.actions.has(name)) {
    throw new Error(`Permission.rules: "${name}" is declared twice`)
  }
  if (kind === "action" && options.filter === undefined) {
    throw new Error(`Permission.rules: "${name}" needs a filter`)
  }
  if (kind === "create" && options.check === undefined) {
    throw new Error(`Permission.rules: "${name}" needs a check`)
  }
  const refs = Condition.refs<unknown, unknown>()
  const allowed = (other: string): Condition.Condition => {
    const filter = self.actions.get(other)?.filter
    if (filter === undefined) {
      throw new Error(`Permission.rules: "${name}" refers to "${other}", which is not an action declared before it`)
    }
    return filter as Condition.Condition
  }
  const input = kind === "action" ? { ...refs, allowed } : refs
  const condition = (rule: ((input: any) => Condition.Input<any>) | undefined) =>
    rule === undefined ? undefined : toCondition(rule(input))
  const actions = new Map(self.actions)
  actions.set(name, {
    name,
    kind,
    resource: self.resource,
    filter: kind === "action" ? condition(options.filter) : undefined,
    check: condition(options.check),
    forbid: condition(options.forbid),
    set: options.set
  })
  return makeRules(self.resource, actions)
}

const RulesProto = {
  [RulesTypeId]: {
    _S: (_: never) => _,
    _Actions: (_: never) => _,
    _Creates: (_: never) => _,
    _R: (_: never) => _,
    _Presets: (_: never) => _
  },
  pipe() {
    return pipeArguments(this, arguments)
  },
  action(this: Any, name: string, options: AnyOptions) {
    return declare(this, name, "action", options)
  },
  create(this: Any, name: string, options: AnyOptions) {
    return declare(this, name, "create", options)
  }
}

const makeRules = (resource: Schema.Top, actions: ReadonlyMap<string, Action>): Any => {
  const self = Object.create(RulesProto)
  self.resource = resource
  self.actions = actions
  return self
}

/**
 * Starts the rules for the actions on one resource type. Declare each action
 * with the `action` or `create` method.
 *
 * **Details**
 *
 * Rule functions are called once, when the action is declared, with
 * references to the principal's and the resource's fields; they record
 * conditions rather than checking values. `set` is the exception: it runs on
 * every `create` and `update` with the real principal.
 *
 * Rules on existing resources refer to the resource type. Create rules refer
 * to the value `create` builds: for a `Model` class, its `insert` variant. For
 * a `Model` class, `update` builds the `update` variant, so an action's `set`
 * fills fields of that variant.
 *
 * Declaring an action name twice is a type error.
 *
 * **Example** (Declaring rules for swap requests)
 *
 * ```ts
 * import { Context, Schema } from "effect"
 * import { Condition, Permission, type Principal } from "effect/permission"
 * import { Model } from "effect/schema"
 *
 * class SwapRequest extends Model.Class<SwapRequest>("SwapRequest")({
 *   id: Model.GeneratedByDb(Schema.Number),
 *   hospitalId: Schema.String,
 *   requesterId: Model.GeneratedByApp(Schema.String),
 *   status: Model.GeneratedByApp(Schema.Literals(["pending", "approved"]))
 * }) {}
 *
 * class CurrentPrincipal extends Context.Service<
 *   CurrentPrincipal,
 *   Principal.Principal<{ readonly hospitalId: string; readonly manager: boolean }>
 * >()("app/CurrentPrincipal") {}
 *
 * const SwapRules = Permission.rules(CurrentPrincipal, SwapRequest)
 *   .action("swaps:read", {
 *     filter: ({ principal, resource: swap }) => Condition.eq(swap.hospitalId, principal.attributes.hospitalId)
 *   })
 *   .action("swaps:approve", {
 *     filter: ({ principal, allowed }) => Condition.and(allowed("swaps:read"), principal.attributes.manager)
 *   })
 *   .create("swaps:create", {
 *     // The payload is SwapRequest.jsonCreate, so `set` fills requesterId and status
 *     set: ({ principal }) => ({ requesterId: principal.subject.id, status: "pending" }),
 *     check: ({ principal, resource: swap }) => Condition.eq(swap.hospitalId, principal.attributes.hospitalId)
 *   })
 * ```
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const rules = <I, A, Id extends string, S extends Schema.Top>(
  _principal: Context.Key<I, Principal.Principal<A, Id>>,
  resource: S
): Rules<A, Id, S, never, never, never, {}> => makeRules(resource, new Map()) as any

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

type OnlyCreate<U, Ac extends string> = Ac extends CreateActionsOf<U> ? Ac : NotACreateAction<Ac>

type NotCreate<U, Ac extends string> = Ac extends CreateActionsOf<U> ? IsACreateAction<Ac> : Ac

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
    action: NotCreate<U, Ac>,
    resource: ResourceOf<U, Ac>
  ): Effect.Effect<Authorizer.Decision, PermissionError.PermissionUnavailable, I | Authorizer.Authorizer>
  /**
   * Fails unless the principal may perform the action on the resource:
   * `Unauthenticated` for guests, `PermissionDenied` otherwise.
   */
  require<Ac extends ActionsOf<U>, Resource extends ResourceOf<U, Ac>>(
    action: NotCreate<U, Ac>,
    resource: Resource
  ): Effect.Effect<Authorized<Ac, Resource>, PermissionError.PermissionError, I | Authorizer.Authorizer>
  /**
   * Returns the condition a resource must satisfy for the principal to perform
   * the action, with the principal's values filled in. A denied plan returns
   * `Condition.never`. For a create action, the condition comes from its
   * `check`.
   */
  filter<Ac extends ActionsOf<U>>(
    action: Ac
  ): Effect.Effect<Condition.Condition<ServicesOf<U>>, PermissionError.PermissionUnavailable, I | Authorizer.Authorizer>
  /**
   * Builds the resource a create action writes, from the payload and the
   * action's `set` presets, then checks it. For a `Model` class the result is
   * its `insert` variant, ready for the repository. A value the schema rejects
   * is a defect.
   *
   * **Details**
   *
   * A signed-in principal's payload leaves out the fields `set` fills. The
   * system principal gets no `set`, so its payload includes them. See
   * {@link PayloadOf}.
   */
  create<Ac extends ActionsOf<U>>(
    action: OnlyCreate<U, Ac>,
    payload: PayloadOf<U, Ac>
  ): Effect.Effect<Authorized<Ac, CreatedOf<U, Ac>>, PermissionError.PermissionError, I | Authorizer.Authorizer>
  /**
   * Checks the resource as it is, builds the value the update writes from the
   * resource, the patch, and the action's `set` presets, then checks the
   * resource as it would be. For a `Model` class the result is its `update`
   * variant, ready for the repository, and fields that variant generates, such
   * as `Model.DateTimeUpdate`, are generated again. A value the schema rejects
   * is a defect.
   *
   * **Details**
   *
   * A signed-in principal's patch leaves out the fields `set` fills. The system
   * principal gets no `set`, so its patch may include them. See
   * {@link PatchOf}.
   */
  update<Ac extends ActionsOf<U>>(
    action: NotCreate<U, Ac>,
    resource: ResourceOf<U, Ac>,
    patch: PatchOf<U, Ac>
  ): Effect.Effect<Authorized<Ac, UpdatedOf<U, Ac>>, PermissionError.PermissionError, I | Authorizer.Authorizer>
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
export const make = <I, A, Id extends string, const Rs extends ReadonlyArray<Any>>(
  principal: Context.Key<I, Principal.Principal<A, Id>>,
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

  const presets = (
    name: string,
    current: Principal.Principal<A, Id>
  ): Effect.Effect<object, PermissionError.PermissionUnavailable> => {
    const set = actions.get(name)?.set
    if (set === undefined || current._tag !== "Authenticated") return Effect.succeed({})
    const values = set({ principal: current })
    return Effect.isEffect(values)
      ? values as Effect.Effect<object, PermissionError.PermissionUnavailable>
      : Effect.succeed(values)
  }

  const create = Effect.fnUntraced(function*(action: string, payload: object) {
    const entry = actions.get(action)
    if (entry?.kind !== "create") {
      return yield* Effect.die(new Error(`Permissions.create: "${action}" is not a create action`))
    }
    const current = yield* principal
    if (current._tag !== "Authenticated") {
      // Guests and the system get no presets, so ask whether they may create
      // at all before building the value
      const authorizer = yield* Authorizer.Authorizer
      yield* orDeny(yield* authorizer.plan({ principal: current, action }))
    }
    const value = yield* Effect.orDie(
      createSchema(entry.resource).makeEffect({ ...payload, ...(yield* presets(action, current)) })
    )
    yield* orDeny(yield* decide("checkWrite", action, value))
    return value as any
  })

  const update = Effect.fnUntraced(function*(action: string, resource: object, patch: object) {
    const entry = actions.get(action)
    if (entry?.kind !== "action") {
      return yield* Effect.die(new Error(`Permissions.update: "${action}" is not an action on existing resources`))
    }
    yield* orDeny(yield* decide("check", action, resource))
    const value = yield* Effect.orDie(
      updateSchema(entry.resource).makeEffect({
        ...carried(entry.resource, resource),
        ...patch,
        ...(yield* presets(action, yield* principal))
      })
    )
    // A `Model` class's update variant lacks some of its fields, so the check
    // sees the resource with the update applied
    yield* orDeny(
      yield* decide("checkWrite", action, isModel(entry.resource) ? merge(resource, value as object) : value)
    )
    return value as any
  })

  const self: Permissions<I, A, Rs[number]> = {
    [PermissionsTypeId]: PermissionsTypeId,
    principal,
    Required: Context.Reference<any>(`${principal.key}/Required`, { defaultValue: () => undefined }),
    actions,
    aliases,
    get layer() {
      return Authorizer.layer(self)
    },
    can: (action, resource) => decide("check", action as string, resource),
    require: (action, resource) =>
      decide("check", action as string, resource).pipe(
        Effect.flatMap(orDeny),
        Effect.as(resource as any)
      ),
    filter: Effect.fnUntraced(function*(action: string) {
      const authorizer = yield* Authorizer.Authorizer
      const decision = yield* authorizer.plan({ principal: yield* principal, action })
      return decision._tag === "Allow" ? decision.condition : Condition.never
    }),
    create: (action, payload) => create(action as string, payload as object),
    update: (action, resource, patch) => update(action as string, resource, patch as object)
  }
  return self
}
