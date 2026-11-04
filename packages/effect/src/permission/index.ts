/**
 * Permission rules, decisions, and enforcement for Effect applications.
 *
 * `Principal` is the caller a check is about. `Condition` is the inspectable
 * expression language rules are written in. `Permission` declares rules per
 * resource type and builds the application's typed `Permissions` object.
 * `Authorizer` is the service that makes decisions, in process or through a
 * remote engine. `PermissionError` holds the errors checks fail with.
 * `PermissionHttpApi`, `PermissionRpc`, and `PermissionSql` enforce rules at
 * HttpApi endpoints, at RPCs, and in SQL queries.
 *
 * @stability experimental
 * @since 4.1.3
 */

// @barrel

/**
 * @stability experimental
 * @since 4.1.3
 */
export * as Authorizer from "./Authorizer.ts"

/**
 * @stability experimental
 * @since 4.1.3
 */
export * as Condition from "./Condition.ts"

/**
 * @stability experimental
 * @since 4.1.3
 */
export * as Permission from "./Permission.ts"

/**
 * @stability experimental
 * @since 4.1.3
 */
export * as PermissionError from "./PermissionError.ts"

/**
 * @stability experimental
 * @since 4.1.3
 */
export * as PermissionHttpApi from "./PermissionHttpApi.ts"

/**
 * @stability experimental
 * @since 4.1.3
 */
export * as PermissionRpc from "./PermissionRpc.ts"

/**
 * @stability experimental
 * @since 4.1.3
 */
export * as PermissionSql from "./PermissionSql.ts"

/**
 * @stability experimental
 * @since 4.1.3
 */
export * as Principal from "./Principal.ts"
