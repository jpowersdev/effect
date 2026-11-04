/**
 * Enforces permission rules at RPCs.
 *
 * Declare an ordinary `RpcMiddleware` that requires the application's
 * principal, provides the `Authorizer` to handlers, and fails with
 * `PermissionError.PermissionError`. Annotate each RPC with the action it
 * requires using `Permissions.Required`, or with `Permission.Public`.
 * {@link layer} implements the middleware.
 *
 * **Gotchas**
 *
 * - RPC middleware only sees the RPC's own annotations. Push group-level
 *   annotations down with `RpcGroup.annotateRpcs`.
 * - A handler can only fail with errors its RPC declares. Add
 *   `PermissionError.PermissionError` to the error of RPCs whose handlers call
 *   `Permissions.require`.
 *
 * **Example** (Declaring the authorization middleware)
 *
 * ```ts
 * import { RpcMiddleware } from "effect/rpc"
 * import { type Authorizer, PermissionError } from "effect/permission"
 *
 * class Authorize extends RpcMiddleware.Service<
 *   Authorize,
 *   {
 *     requires: CurrentPrincipal
 *     provides: Authorizer.Authorizer
 *   }
 * >()("app/Authorize", {
 *   error: PermissionError.PermissionError
 * }) {}
 * ```
 *
 * @stability experimental
 * @since 4.1.3
 */
import * as Context from "../Context.ts"
import * as Effect from "../Effect.ts"
import * as Layer from "../Layer.ts"
import type * as Rpc from "../rpc/Rpc.ts"
import type * as RpcGroup from "../rpc/RpcGroup.ts"
import type * as RpcMiddleware from "../rpc/RpcMiddleware.ts"
import * as Authorizer from "./Authorizer.ts"
import * as Permission from "./Permission.ts"
import * as PermissionError from "./PermissionError.ts"

/**
 * Lists the configuration problems of an RPC group: RPCs with no
 * `Permissions.Required` annotation, RPCs that require an action but are not
 * guarded by the middleware, and RPCs that require an unknown action.
 *
 * @stability experimental
 * @category validation
 * @since 4.1.3
 */
export const validate = <I, A, U extends Permission.Any, Rpcs extends Rpc.Any>(
  group: RpcGroup.RpcGroup<Rpcs>,
  middleware: Context.Key<any, any>,
  permissions: Permission.Permissions<I, A, U>
): ReadonlyArray<string> => {
  const problems: Array<string> = []
  for (const rpc of group.requests.values() as Iterable<Rpc.AnyWithProps>) {
    const required = Context.getOrUndefined(rpc.annotations, permissions.Required)
    if (required === undefined) {
      problems.push(`${rpc._tag} has no required action; annotate it with an action or Permission.Public`)
    } else if (required !== Permission.Public) {
      if (!permissions.actions.has(required)) problems.push(`${rpc._tag} requires the unknown action "${required}"`)
      if (!rpc.middlewares.has(middleware as RpcMiddleware.AnyServiceWithProps)) {
        problems.push(`${rpc._tag} requires "${required}" but is not guarded by ${middleware.key}`)
      }
    }
  }
  return problems
}

/**
 * Implements an authorization middleware for RPCs.
 *
 * **Details**
 *
 * For each request the middleware reads the action the RPC requires, lets
 * `Permission.Public` RPCs through, and asks the authorizer whether the
 * principal could perform the action on any resource. An RPC with no
 * annotation is denied. Allowed requests run with the `Authorizer` provided,
 * so declare `provides: Authorizer.Authorizer` on the middleware. Checks on a
 * specific resource belong in the handler, with `Permissions.require`.
 *
 * With `group`, building the layer fails with a defect listing every
 * configuration problem found by {@link validate}.
 *
 * @stability experimental
 * @category layers
 * @since 4.1.3
 */
export const layer = <Self, I, A, U extends Permission.Any, Rpcs extends Rpc.Any = never>(
  middleware: Context.Key<Self, any>,
  permissions: Permission.Permissions<I, A, U>,
  options?: {
    readonly group?: RpcGroup.RpcGroup<Rpcs> | undefined
  }
): Layer.Layer<Self, never, Authorizer.Authorizer> =>
  Layer.effect(
    middleware,
    Effect.gen(function*() {
      if (options?.group !== undefined) {
        const problems = validate(options.group, middleware, permissions)
        if (problems.length > 0) {
          return yield* Effect.die(new Error(`PermissionRpc.layer:\n  ${problems.join("\n  ")}`))
        }
      }
      const authorizer = yield* Authorizer.Authorizer
      const implementation: RpcMiddleware.RpcMiddleware<Authorizer.Authorizer, PermissionError.PermissionError, I> =
        Effect.fnUntraced(
          function*(effect, { rpc }) {
            const required = Context.getOrUndefined(rpc.annotations, permissions.Required)
            const handler = Effect.provideService(effect, Authorizer.Authorizer, authorizer)
            if (required === Permission.Public) return yield* handler
            if (required === undefined) {
              return yield* new PermissionError.PermissionDenied({ action: rpc._tag, reason: "NoPermission" })
            }
            const decision = yield* authorizer.plan({ principal: yield* permissions.principal, action: required })
            if (decision._tag === "Deny") {
              return yield* new PermissionError.PermissionDenied({ action: required, reason: decision.reason })
            }
            return yield* handler
          }
        )
      return implementation as any
    })
  )
