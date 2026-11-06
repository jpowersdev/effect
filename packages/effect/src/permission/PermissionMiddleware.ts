/**
 * Enforces permission rules at HttpApi endpoints and at RPCs.
 *
 * Declare an ordinary `HttpApiMiddleware` or `RpcMiddleware` that requires the
 * application's principal, provides the `Authorizer` to handlers, and fails
 * with the permission errors: 401 for guests, 403 for callers who aren't
 * allowed, and 503 when a decision can't be made. Annotate each endpoint,
 * group, or RPC with the action it requires using `Permissions.Required`, or
 * with `Permission.Public`. {@link layerHttpApi} and {@link layerRpc}
 * implement the middleware. Handlers may fail with the middleware's errors,
 * so `Permissions.require` works inside them.
 *
 * **Details**
 *
 * The middleware runs before the handler has loaded anything, so it can only
 * ask whether the principal could perform the action on any resource. Checks
 * on a specific resource belong in the handler, with `Permissions.require`.
 *
 * **Gotchas**
 *
 * - HttpApi middleware must declare `error: PermissionError.errors`, the list,
 *   so each error keeps its status. RPC middleware takes one schema, so it
 *   declares `error: PermissionError.PermissionError`.
 * - RPC middleware only sees the RPC's own annotations. Push group-level
 *   annotations down with `RpcGroup.annotateRpcs`.
 *
 * **Example** (Declaring the authorization middleware)
 *
 * ```ts
 * import { HttpApiMiddleware } from "effect/http-api"
 * import { type Authorizer, PermissionError } from "effect/permission"
 * import { RpcMiddleware } from "effect/rpc"
 *
 * class Authorize extends HttpApiMiddleware.Service<
 *   Authorize,
 *   {
 *     requires: CurrentPrincipal
 *     provides: Authorizer.Authorizer
 *   }
 * >()("app/Authorize", {
 *   error: PermissionError.errors
 * }) {}
 *
 * class RpcAuthorize extends RpcMiddleware.Service<
 *   RpcAuthorize,
 *   {
 *     requires: CurrentPrincipal
 *     provides: Authorizer.Authorizer
 *   }
 * >()("app/RpcAuthorize", {
 *   error: PermissionError.PermissionError
 * }) {}
 * ```
 *
 * @stability experimental
 * @since 4.1.3
 */
import * as Context from "../Context.ts"
import * as Effect from "../Effect.ts"
import * as HttpApi from "../http-api/HttpApi.ts"
import type * as HttpApiGroup from "../http-api/HttpApiGroup.ts"
import type * as HttpApiMiddleware from "../http-api/HttpApiMiddleware.ts"
import * as Layer from "../Layer.ts"
import type * as Rpc from "../rpc/Rpc.ts"
import type * as RpcGroup from "../rpc/RpcGroup.ts"
import type * as RpcMiddleware from "../rpc/RpcMiddleware.ts"
import * as Authorizer from "./Authorizer.ts"
import * as Permission from "./Permission.ts"
import * as PermissionError from "./PermissionError.ts"

type Required = string | Permission.Public | undefined

// The problems with one endpoint or RPC, once its required action is known
const problemsOf = <I, A, U extends Permission.Any>(
  permissions: Permission.Permissions<I, A, U>,
  middleware: Context.Key<any, any>,
  label: string,
  required: Required,
  guarded: boolean
): ReadonlyArray<string> => {
  if (required === undefined) {
    return [`${label} has no required action; annotate it with an action or Permission.Public`]
  }
  if (required === Permission.Public) return []
  const problems: Array<string> = []
  if (!permissions.actions.has(required)) problems.push(`${label} requires the unknown action "${required}"`)
  if (!guarded) problems.push(`${label} requires "${required}" but is not guarded by ${middleware.key}`)
  return problems
}

// Both middleware make the same decision; only where the annotation lives differs
const enforce = <I, A, U extends Permission.Any, X, E, R>(
  permissions: Permission.Permissions<I, A, U>,
  authorizer: Authorizer.Authorizer["Service"],
  label: string,
  required: Required,
  effect: Effect.Effect<X, E, R>
): Effect.Effect<
  X,
  E | PermissionError.Unauthenticated | PermissionError.PermissionDenied | PermissionError.PermissionUnavailable,
  Exclude<R, Authorizer.Authorizer> | I
> =>
  Effect.gen(function*() {
    const handler = Effect.provideService(effect, Authorizer.Authorizer, authorizer)
    if (required === Permission.Public) return yield* handler
    if (required === undefined) {
      return yield* new PermissionError.PermissionDenied({ action: label, reason: "NoPermission" })
    }
    const decision = yield* authorizer.plan({ principal: yield* permissions.principal, action: required })
    if (decision._tag === "Deny") {
      return yield* Authorizer.toError(decision)
    }
    return yield* handler
  })

const make = <Self>(
  name: string,
  middleware: Context.Key<Self, any>,
  validate: (() => ReadonlyArray<string>) | undefined,
  implement: (authorizer: Authorizer.Authorizer["Service"]) => unknown
): Layer.Layer<Self, never, Authorizer.Authorizer> =>
  Layer.effect(
    middleware,
    Effect.gen(function*() {
      const problems = validate?.() ?? []
      if (problems.length > 0) {
        return yield* Effect.die(new Error(`PermissionMiddleware.${name}:\n  ${problems.join("\n  ")}`))
      }
      return implement(yield* Authorizer.Authorizer) as any
    })
  )

// -----------------------------------------------------------------------------
// HttpApi
// -----------------------------------------------------------------------------

const requiredFor = <I, A, U extends Permission.Any>(
  permissions: Permission.Permissions<I, A, U>,
  endpoint: Context.Context<never>,
  group: Context.Context<never>
): Required =>
  Context.getOrUndefined(endpoint, permissions.Required) ?? Context.getOrUndefined(group, permissions.Required)

/**
 * Lists the configuration problems of an API: endpoints with no
 * `Permissions.Required` annotation, endpoints that require an action but are
 * not guarded by the middleware, and endpoints that require an unknown action.
 *
 * **Gotchas**
 *
 * Annotations on the whole `HttpApi` never reach middleware, so they are
 * reported as missing.
 *
 * @stability experimental
 * @category validation
 * @since 4.1.3
 */
export const validateHttpApi = <
  I,
  A,
  U extends Permission.Any,
  ApiId extends string,
  Groups extends HttpApiGroup.Constraint
>(
  api: HttpApi.HttpApi<ApiId, Groups>,
  middleware: Context.Key<any, any>,
  permissions: Permission.Permissions<I, A, U>
): ReadonlyArray<string> => {
  const problems: Array<string> = []
  HttpApi.reflect(api, {
    onGroup() {},
    onEndpoint({ endpoint, group, mergedAnnotations, middleware: guards }) {
      const label = `${group.identifier}.${endpoint.identifier}`
      const required = requiredFor(permissions, endpoint.annotations, group.annotations)
      if (required === undefined && Context.getOrUndefined(mergedAnnotations, permissions.Required) !== undefined) {
        problems.push(
          `${label} is annotated on the HttpApi, which middleware never sees; annotate the group or endpoint`
        )
        return
      }
      problems.push(
        ...problemsOf(permissions, middleware, label, required, guards.has(middleware as HttpApiMiddleware.AnyService))
      )
    }
  })
  return problems
}

/**
 * Implements an authorization middleware for HttpApi endpoints.
 *
 * **Details**
 *
 * For each request the middleware reads the action the endpoint or its group
 * requires, lets `Permission.Public` endpoints through, and asks the
 * authorizer whether the principal could perform the action on any resource.
 * An endpoint with no annotation is denied. Allowed requests run with the
 * `Authorizer` provided, so declare `provides: Authorizer.Authorizer` on the
 * middleware.
 *
 * With `api`, building the layer fails with a defect listing every
 * configuration problem found by {@link validateHttpApi}.
 *
 * @stability experimental
 * @category layers
 * @since 4.1.3
 */
export const layerHttpApi = <
  Self,
  I,
  A,
  U extends Permission.Any,
  ApiId extends string = string,
  Groups extends HttpApiGroup.Constraint = never
>(
  middleware: Context.Key<Self, any>,
  permissions: Permission.Permissions<I, A, U>,
  options?: {
    readonly api?: HttpApi.HttpApi<ApiId, Groups> | undefined
  }
): Layer.Layer<Self, never, Authorizer.Authorizer> => {
  const api = options?.api
  return make(
    "layerHttpApi",
    middleware,
    api === undefined ? undefined : () => validateHttpApi(api, middleware, permissions),
    (authorizer): HttpApiMiddleware.HttpApiMiddleware<Authorizer.Authorizer, any, I> =>
    (httpEffect, { endpoint, group }) =>
      enforce(
        permissions,
        authorizer,
        `${group.identifier}.${endpoint.identifier}`,
        requiredFor(permissions, endpoint.annotations, group.annotations),
        httpEffect
      )
  )
}

// -----------------------------------------------------------------------------
// Rpc
// -----------------------------------------------------------------------------

/**
 * Lists the configuration problems of an RPC group: RPCs with no
 * `Permissions.Required` annotation, RPCs that require an action but are not
 * guarded by the middleware, and RPCs that require an unknown action.
 *
 * @stability experimental
 * @category validation
 * @since 4.1.3
 */
export const validateRpc = <I, A, U extends Permission.Any, Rpcs extends Rpc.Any>(
  group: RpcGroup.RpcGroup<Rpcs>,
  middleware: Context.Key<any, any>,
  permissions: Permission.Permissions<I, A, U>
): ReadonlyArray<string> =>
  Array.from(group.requests.values() as Iterable<Rpc.AnyWithProps>).flatMap((rpc) =>
    problemsOf(
      permissions,
      middleware,
      rpc._tag,
      Context.getOrUndefined(rpc.annotations, permissions.Required),
      rpc.middlewares.has(middleware as RpcMiddleware.AnyServiceWithProps)
    )
  )

/**
 * Implements an authorization middleware for RPCs.
 *
 * **Details**
 *
 * For each request the middleware reads the action the RPC requires, lets
 * `Permission.Public` RPCs through, and asks the authorizer whether the
 * principal could perform the action on any resource. An RPC with no
 * annotation is denied. Allowed requests run with the `Authorizer` provided,
 * so declare `provides: Authorizer.Authorizer` on the middleware.
 *
 * With `group`, building the layer fails with a defect listing every
 * configuration problem found by {@link validateRpc}.
 *
 * @stability experimental
 * @category layers
 * @since 4.1.3
 */
export const layerRpc = <Self, I, A, U extends Permission.Any, Rpcs extends Rpc.Any = never>(
  middleware: Context.Key<Self, any>,
  permissions: Permission.Permissions<I, A, U>,
  options?: {
    readonly group?: RpcGroup.RpcGroup<Rpcs> | undefined
  }
): Layer.Layer<Self, never, Authorizer.Authorizer> => {
  const group = options?.group
  return make(
    "layerRpc",
    middleware,
    group === undefined ? undefined : () => validateRpc(group, middleware, permissions),
    (authorizer): RpcMiddleware.RpcMiddleware<Authorizer.Authorizer, PermissionError.PermissionError, I> =>
    (effect, { rpc }) =>
      enforce(
        permissions,
        authorizer,
        rpc._tag,
        Context.getOrUndefined(rpc.annotations, permissions.Required),
        effect
      )
  )
}
