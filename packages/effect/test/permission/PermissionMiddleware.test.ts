import { assert, describe, it } from "@effect/vitest"
import { Effect, Exit, FileSystem, Layer, Path, Schema } from "effect"
import { Etag, HttpPlatform, HttpRouter } from "effect/http"
import {
  HttpApi,
  HttpApiBuilder,
  HttpApiEndpoint,
  HttpApiGroup,
  HttpApiMiddleware,
  HttpApiTest,
  OpenApi
} from "effect/http-api"
import { Authorizer, Permission, PermissionError, PermissionMiddleware, Principal } from "effect/permission"
import { Rpc, RpcGroup, RpcMiddleware, RpcTest } from "effect/rpc"
import {
  CurrentPrincipal,
  manager,
  type Member,
  memberships,
  nurse,
  Permissions,
  swap,
  SwapRequest,
  Unit,
  units
} from "./utils.ts"

// -----------------------------------------------------------------------------
// HttpApi
// -----------------------------------------------------------------------------

class Authentication extends HttpApiMiddleware.Service<
  Authentication,
  { provides: CurrentPrincipal }
>()("test/permission/Authentication") {}

class Authorize extends HttpApiMiddleware.Service<
  Authorize,
  {
    requires: CurrentPrincipal
    provides: Authorizer.Authorizer
  }
>()("test/permission/Authorize", {
  error: PermissionError.errors
}) {}

const UnitsGroup = HttpApiGroup.make("units")
  .add(
    HttpApiEndpoint.get("list", "/units", { success: Schema.Array(Unit) })
      .annotate(Permissions.Required, "units:read"),
    HttpApiEndpoint.patch("rename", "/units/:id", {
      params: { id: Schema.String },
      payload: Schema.Struct({ name: Schema.String }),
      success: Unit
    }).annotate(Permissions.Required, "units:update"),
    HttpApiEndpoint.get("health", "/health", { success: Schema.String })
      .annotate(Permissions.Required, Permission.Public)
  )
  .middleware(Authorize)
  .middleware(Authentication)

const Api = HttpApi.make("api").add(UnitsGroup)

const UnitsLive = HttpApiBuilder.group(Api, "units", (handlers) =>
  handlers
    .handle("list", () =>
      Effect.filter(units, (unit) =>
        Permissions.can("units:read", unit).pipe(Effect.map(Authorizer.isAllow))).pipe(
          Effect.orDie
        ))
    .handle("rename", ({ params, payload }) =>
      Permissions.update(
        "units:update",
        units.find((unit) =>
          unit.id === params.id
        )!,
        { name: payload.name }
      ))
    .handle("health", () => Effect.succeed("ok")))

const TestServices = Layer.mergeAll(Path.layer, Etag.layerWeak, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({}))
)

const httpClient = (principal: Principal.Principal<Member>) =>
  HttpApiTest.groups(Api, ["units"]).pipe(
    Effect.provide(UnitsLive),
    Effect.provide(PermissionMiddleware.layerHttpApi(Authorize, Permissions, { api: Api })),
    Effect.provide(
      Layer.succeed(Authentication, (httpEffect) => Effect.provideService(httpEffect, CurrentPrincipal, principal))
    ),
    Effect.provide(Permissions.layer.pipe(Layer.provide(Authorizer.layerRelationsMemory(memberships)))),
    Effect.provide(TestServices)
  )

// -----------------------------------------------------------------------------
// Rpc
// -----------------------------------------------------------------------------

class RpcAuthentication extends RpcMiddleware.Service<
  RpcAuthentication,
  { provides: CurrentPrincipal }
>()("test/permission/RpcAuthentication") {}

class RpcAuthorize extends RpcMiddleware.Service<
  RpcAuthorize,
  {
    requires: CurrentPrincipal
    provides: Authorizer.Authorizer
  }
>()("test/permission/RpcAuthorize", {
  error: PermissionError.PermissionError
}) {}

// The RPCs don't repeat the permission errors: handlers may fail with their
// middleware's errors
const AcceptSwap = Rpc.make("AcceptSwap", { payload: { id: Schema.String }, success: SwapRequest })
  .annotate(Permissions.Required, "swaps:accept")
const ApproveSwap = Rpc.make("ApproveSwap", { payload: { id: Schema.String }, success: SwapRequest })
  .annotate(Permissions.Required, "swaps:approve")

const SwapRpcs = RpcGroup.make(AcceptSwap, ApproveSwap).middleware(RpcAuthorize).middleware(RpcAuthentication)

const swaps = [swap({ id: "s-1" }), swap({ id: "s-2", status: "accepted" })]
const find = (id: string) => swaps.find((swap) => swap.id === id)!

const SwapsLive = SwapRpcs.toLayer({
  AcceptSwap: ({ id }) => Permissions.require("swaps:accept", find(id)),
  ApproveSwap: ({ id }) => Permissions.require("swaps:approve", find(id))
})

const rpcClient = (principal: Principal.Principal<Member>) =>
  RpcTest.makeClient(SwapRpcs).pipe(
    Effect.provide(SwapsLive),
    Effect.provide(PermissionMiddleware.layerRpc(RpcAuthorize, Permissions, { group: SwapRpcs })),
    Effect.provide(
      Layer.succeed(RpcAuthentication, (effect) => Effect.provideService(effect, CurrentPrincipal, principal))
    ),
    Effect.provide(Permissions.layer.pipe(Layer.provide(Authorizer.layerRelationsMemory(memberships))))
  )

describe("PermissionMiddleware", () => {
  describe("layerHttpApi", () => {
    it("names the permission errors plainly in OpenAPI documents", () => {
      const names = Object.keys(OpenApi.fromApi(Api).components.schemas)
      for (const name of ["UnauthenticatedEncoded", "PermissionDeniedEncoded", "PermissionUnavailableEncoded"]) {
        assert.include(names, name)
      }
    })

    it.effect("lets allowed requests through and filters in the handler", () =>
      Effect.gen(function*() {
        const api = yield* httpClient(nurse)
        const visible = yield* api.units.list()
        assert.deepStrictEqual(visible.map((unit) => unit.id), ["u-1", "u-2"])
      }))

    it.effect("rejects an action the principal could never perform before the handler runs", () =>
      Effect.gen(function*() {
        const api = yield* httpClient(nurse)
        const error = yield* Effect.flip(api.units.rename({ params: { id: "u-1" }, payload: { name: "x" } }))
        assert.instanceOf(error, PermissionError.PermissionDenied)
        assert.strictEqual(error.reason, "NoPermission")
      }))

    it.effect("checks the resource in the handler", () =>
      Effect.gen(function*() {
        const api = yield* httpClient(manager)
        const renamed = yield* api.units.rename({ params: { id: "u-1" }, payload: { name: "Intensive Care" } })
        assert.strictEqual(renamed.name, "Intensive Care")
        const error = yield* Effect.flip(api.units.rename({ params: { id: "u-3" }, payload: { name: "x" } }))
        assert.instanceOf(error, PermissionError.PermissionDenied)
      }))

    it.effect("lets guests through to public endpoints and answers 401 elsewhere", () =>
      Effect.gen(function*() {
        const api = yield* httpClient(Principal.guest)
        assert.strictEqual(yield* api.units.health(), "ok")
        const error = yield* Effect.flip(api.units.list())
        assert.instanceOf(error, PermissionError.Unauthenticated)
        assert.strictEqual(error.action, "units:read")
      }))

    it("responds with 401 for guests and 403 for callers who aren't allowed", async () => {
      const status = async (principal: Principal.Principal<Member>, path: string, init?: RequestInit) => {
        const { dispose, handler } = HttpRouter.toWebHandler(
          HttpApiBuilder.layer(Api).pipe(
            Layer.provide(UnitsLive),
            Layer.provide(PermissionMiddleware.layerHttpApi(Authorize, Permissions, { api: Api })),
            Layer.provide(
              Layer.succeed(
                Authentication,
                (httpEffect) => Effect.provideService(httpEffect, CurrentPrincipal, principal)
              )
            ),
            Layer.provide(Permissions.layer.pipe(Layer.provide(Authorizer.layerRelationsMemory(memberships)))),
            Layer.provide(TestServices)
          ),
          { disableLogger: true }
        )
        try {
          return (await handler(new Request(`http://localhost${path}`, init))).status
        } finally {
          await dispose()
        }
      }
      assert.strictEqual(await status(Principal.guest, "/units"), 401)
      assert.strictEqual(
        await status(nurse, "/units/u-1", {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ name: "x" })
        }),
        403
      )
      assert.strictEqual(await status(nurse, "/units"), 200)
    })

    it.effect("fails to start when an endpoint is not covered", () =>
      Effect.gen(function*() {
        const Unguarded = HttpApi.make("unguarded").add(
          HttpApiGroup.make("units").add(
            HttpApiEndpoint.get("list", "/units", { success: Schema.String }).annotate(
              Permissions.Required,
              "units:read"
            ),
            HttpApiEndpoint.get("other", "/other", { success: Schema.String })
          )
        )
        assert.deepStrictEqual(PermissionMiddleware.validateHttpApi(Unguarded, Authorize, Permissions), [
          "units.list requires \"units:read\" but is not guarded by test/permission/Authorize",
          "units.other has no required action; annotate it with an action or Permission.Public"
        ])
        const exit = yield* Effect.exit(
          Layer.build(PermissionMiddleware.layerHttpApi(Authorize, Permissions, { api: Unguarded })).pipe(
            Effect.provide(Authorizer.layerDenyAll),
            Effect.scoped
          )
        )
        assert.isTrue(Exit.hasDies(exit))
      }))
  })

  describe("layerRpc", () => {
    it.effect("allows and denies through the middleware and the handler", () =>
      Effect.gen(function*() {
        const asNurse = yield* rpcClient(nurse)
        assert.strictEqual((yield* asNurse.AcceptSwap({ id: "s-1" })).id, "s-1")
        const denied = yield* Effect.flip(asNurse.ApproveSwap({ id: "s-2" }))
        assert.strictEqual(denied._tag, "PermissionDenied")

        const asManager = yield* rpcClient(manager)
        assert.strictEqual((yield* asManager.ApproveSwap({ id: "s-2" })).id, "s-2")
        // The middleware lets a manager through, and the handler denies the
        // pending swap with an error its RPC doesn't declare
        const pending = yield* Effect.flip(asManager.ApproveSwap({ id: "s-1" }))
        assert.instanceOf(pending, PermissionError.PermissionDenied)
      }))

    it.effect("applies limits at the middleware", () =>
      Effect.gen(function*() {
        const viaText = yield* rpcClient(Principal.withLimit(manager, ["swaps:respond"]))
        const denied = yield* Effect.flip(viaText.ApproveSwap({ id: "s-2" }))
        assert.strictEqual(denied._tag, "PermissionDenied")
        if (denied._tag === "PermissionDenied") assert.strictEqual(denied.reason, "Limit")
      }))

    it.effect("fails to start when an RPC is not covered", () =>
      Effect.gen(function*() {
        const Unannotated = RpcGroup.make(Rpc.make("Ping", { success: Schema.String })).middleware(RpcAuthorize)
        assert.deepStrictEqual(PermissionMiddleware.validateRpc(Unannotated, RpcAuthorize, Permissions), [
          "Ping has no required action; annotate it with an action or Permission.Public"
        ])
        const exit = yield* Effect.exit(
          Layer.build(PermissionMiddleware.layerRpc(RpcAuthorize, Permissions, { group: Unannotated })).pipe(
            Effect.provide(Authorizer.layerDenyAll),
            Effect.scoped
          )
        )
        assert.isTrue(Exit.hasDies(exit))
      }))
  })
})
