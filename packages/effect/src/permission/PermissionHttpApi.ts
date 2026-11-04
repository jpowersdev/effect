/**
 * Enforces permission rules at HttpApi endpoints.
 *
 * Declare an ordinary `HttpApiMiddleware` that requires the application's
 * principal, provides the `Authorizer` to handlers, and fails with
 * `PermissionError.errors`: 401 for guests, 403 for callers who aren't
 * allowed, and 503 when a decision can't be made.
 * Annotate each endpoint or group with the action it requires using
 * `Permissions.Required`, or with `Permission.Public`. {@link layer} implements
 * the middleware. Because the middleware declares those errors, handlers may
 * fail with them too, so `Permissions.require` works inside handlers.
 *
 * **Details**
 *
 * HttpApi middleware runs before params, query, headers, and payload are
 * decoded, so the middleware can only ask whether the principal could perform
 * the action on any resource. Checks on a specific resource belong in the
 * handler, with `Permissions.require`.
 *
 * **Example** (Declaring the authorization middleware)
 *
 * ```ts
 * import { HttpApiMiddleware } from "effect/http-api"
 * import { type Authorizer, PermissionError } from "effect/permission"
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
import * as Authorizer from "./Authorizer.ts"
import * as Permission from "./Permission.ts"
import * as PermissionError from "./PermissionError.ts"

const requiredFor = <I, A, U extends Permission.Any>(
  permissions: Permission.Permissions<I, A, U>,
  endpoint: Context.Context<never>,
  group: Context.Context<never>
): string | Permission.Public | undefined =>
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
export const validate = <I, A, U extends Permission.Any, ApiId extends string, Groups extends HttpApiGroup.Constraint>(
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
      if (required === undefined) {
        problems.push(
          Context.getOrUndefined(mergedAnnotations, permissions.Required) === undefined
            ? `${label} has no required action; annotate it with an action or Permission.Public`
            : `${label} is annotated on the HttpApi, which middleware never sees; annotate the group or endpoint`
        )
      } else if (required !== Permission.Public) {
        if (!permissions.actions.has(required)) problems.push(`${label} requires the unknown action "${required}"`)
        if (!guards.has(middleware as HttpApiMiddleware.AnyService)) {
          problems.push(`${label} requires "${required}" but is not guarded by ${middleware.key}`)
        }
      }
    }
  })
  return problems
}

/**
 * Implements an authorization middleware for HttpApi endpoints.
 *
 * **Details**
 *
 * For each request the middleware reads the action the endpoint requires,
 * lets `Permission.Public` endpoints through, and asks the authorizer whether
 * the principal could perform the action on any resource. An endpoint with no
 * annotation is denied. Allowed requests run with the `Authorizer` provided,
 * so declare `provides: Authorizer.Authorizer` on the middleware.
 *
 * With `api`, building the layer fails with a defect listing every
 * configuration problem found by {@link validate}.
 *
 * @stability experimental
 * @category layers
 * @since 4.1.3
 */
export const layer = <
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
): Layer.Layer<Self, never, Authorizer.Authorizer> =>
  Layer.effect(
    middleware,
    Effect.gen(function*() {
      if (options?.api !== undefined) {
        const problems = validate(options.api, middleware, permissions)
        if (problems.length > 0) {
          return yield* Effect.die(new Error(`PermissionHttpApi.layer:\n  ${problems.join("\n  ")}`))
        }
      }
      const authorizer = yield* Authorizer.Authorizer
      const implementation: HttpApiMiddleware.HttpApiMiddleware<Authorizer.Authorizer, any, I> = Effect.fnUntraced(
        function*(httpEffect, { endpoint, group }) {
          const required = requiredFor(permissions, endpoint.annotations, group.annotations)
          const handler = Effect.provideService(httpEffect, Authorizer.Authorizer, authorizer)
          if (required === Permission.Public) return yield* handler
          if (required === undefined) {
            return yield* new PermissionError.PermissionDenied({
              action: `${group.identifier}.${endpoint.identifier}`,
              reason: "NoPermission"
            })
          }
          const decision = yield* authorizer.plan({ principal: yield* permissions.principal, action: required })
          if (decision._tag === "Deny") {
            return yield* Authorizer.toError(decision)
          }
          return yield* handler
        }
      )
      return implementation as any
    })
  )
