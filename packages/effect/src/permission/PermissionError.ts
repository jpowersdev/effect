/**
 * The errors permission checks fail with, as Schema errors so they can be
 * declared on HttpApi endpoints and RPCs and decoded by clients.
 *
 * Declare {@link errors} as the error of an HttpApi authorization middleware,
 * and {@link PermissionError} as the error of an RPC one.
 * A guest asking for a protected action fails with {@link Unauthenticated}
 * (401); a signed-in caller who isn't allowed fails with
 * {@link PermissionDenied} (403).
 *
 * @stability experimental
 * @since 4.1.3
 */
import * as Schema from "../Schema.ts"

/**
 * The schema for why a signed-in caller was denied.
 *
 * **Details**
 *
 * - `NoPermission`: no rule allows the action on this resource.
 * - `Forbidden`: a `forbid` rule matched.
 * - `Limit`: the request's credential is not allowed to use this action.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export const DenyReason = Schema.Literals(["NoPermission", "Forbidden", "Limit"])

/**
 * Why a signed-in caller was denied: `NoPermission`, `Forbidden`, or `Limit`.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type DenyReason = typeof DenyReason.Type

/**
 * The caller is a guest and the action needs a signed-in principal. Responds
 * with 401.
 *
 * @stability experimental
 * @category errors
 * @since 4.1.3
 */
// Each error's `identifier` names it in OpenAPI documents, which would
// otherwise show `effect_permission_UnauthenticatedEncoded`
export class Unauthenticated extends Schema.TaggedError<Unauthenticated>("effect/permission/Unauthenticated")(
  "Unauthenticated",
  { action: Schema.String },
  { httpApiStatus: 401, identifier: "Unauthenticated" }
) {}

/**
 * The signed-in caller is not allowed to perform the action. Responds with
 * 403.
 *
 * @stability experimental
 * @category errors
 * @since 4.1.3
 */
export class PermissionDenied extends Schema.TaggedError<PermissionDenied>("effect/permission/PermissionDenied")(
  "PermissionDenied",
  {
    action: Schema.String,
    reason: DenyReason
  },
  { httpApiStatus: 403, identifier: "PermissionDenied" }
) {}

/**
 * The decision could not be made, for example because a relation lookup or a
 * custom condition failed. Responds with 503. Failure to decide is never an
 * allow or a deny.
 *
 * @stability experimental
 * @category errors
 * @since 4.1.3
 */
export class PermissionUnavailable
  extends Schema.TaggedError<PermissionUnavailable>("effect/permission/PermissionUnavailable")(
    "PermissionUnavailable",
    {},
    { httpApiStatus: 503, identifier: "PermissionUnavailable" }
  )
{}

/**
 * Every permission error, as a list of schemas, for `HttpApiMiddleware`.
 *
 * **Gotchas**
 *
 * Declare the list, not the {@link PermissionError} union, on HttpApi
 * middleware: a union schema loses each error's HTTP status and responds with
 * 500.
 *
 * @stability experimental
 * @category schemas
 * @since 4.1.3
 */
export const errors = [Unauthenticated, PermissionDenied, PermissionUnavailable] as const

/**
 * Every permission error, as one schema, for `RpcMiddleware`, which accepts a
 * single error schema.
 *
 * @stability experimental
 * @category schemas
 * @since 4.1.3
 */
export const PermissionError = Schema.Union([Unauthenticated, PermissionDenied, PermissionUnavailable])

/**
 * Every permission error.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type PermissionError = Unauthenticated | PermissionDenied | PermissionUnavailable
