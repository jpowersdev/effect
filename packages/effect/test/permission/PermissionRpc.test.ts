import { assert, describe, it } from "@effect/vitest"
import { Effect, Exit, Layer, Schema } from "effect"
import { Authorizer, PermissionError, PermissionRpc, Principal } from "effect/permission"
import { Rpc, RpcGroup, RpcMiddleware, RpcTest } from "effect/rpc"
import { CurrentPrincipal, manager, type Member, memberships, nurse, Permissions, swap, SwapRequest } from "./utils.ts"

class Authentication extends RpcMiddleware.Service<
  Authentication,
  { provides: CurrentPrincipal }
>()("test/permission/RpcAuthentication") {}

class Authorize extends RpcMiddleware.Service<
  Authorize,
  {
    requires: CurrentPrincipal
    provides: Authorizer.Authorizer
  }
>()("test/permission/RpcAuthorize", {
  error: PermissionError.PermissionError
}) {}

const AcceptSwap = Rpc.make("AcceptSwap", {
  payload: { id: Schema.String },
  success: SwapRequest,
  error: PermissionError.PermissionError
})
  .annotate(Permissions.Required, "swaps:accept")
const ApproveSwap = Rpc.make("ApproveSwap", {
  payload: { id: Schema.String },
  success: SwapRequest,
  error: PermissionError.PermissionError
})
  .annotate(Permissions.Required, "swaps:approve")

const SwapRpcs = RpcGroup.make(AcceptSwap, ApproveSwap).middleware(Authorize).middleware(Authentication)

const swaps = [swap({ id: "s-1" }), swap({ id: "s-2", status: "accepted" })]
const find = (id: string) => swaps.find((swap) => swap.id === id)!

const SwapsLive = SwapRpcs.toLayer({
  AcceptSwap: ({ id }) => Permissions.require("swaps:accept", find(id)),
  ApproveSwap: ({ id }) => Permissions.require("swaps:approve", find(id))
})

const client = (principal: Principal.Principal<Member>) =>
  RpcTest.makeClient(SwapRpcs).pipe(
    Effect.provide(SwapsLive),
    Effect.provide(PermissionRpc.layer(Authorize, Permissions, { group: SwapRpcs })),
    Effect.provide(
      Layer.succeed(Authentication, (effect) => Effect.provideService(effect, CurrentPrincipal, principal))
    ),
    Effect.provide(Permissions.layer.pipe(Layer.provide(Authorizer.layerRelationsMemory(memberships))))
  )

describe("PermissionRpc", () => {
  it.effect("allows and denies through the middleware and the handler", () =>
    Effect.gen(function*() {
      const asNurse = yield* client(nurse)
      assert.strictEqual((yield* asNurse.AcceptSwap({ id: "s-1" })).id, "s-1")
      const denied = yield* Effect.flip(asNurse.ApproveSwap({ id: "s-2" }))
      assert.strictEqual(denied._tag, "PermissionDenied")

      const asManager = yield* client(manager)
      assert.strictEqual((yield* asManager.ApproveSwap({ id: "s-2" })).id, "s-2")
    }))

  it.effect("applies limits at the middleware", () =>
    Effect.gen(function*() {
      const viaText = yield* client(Principal.withLimit(manager, ["swaps:respond"]))
      const denied = yield* Effect.flip(viaText.ApproveSwap({ id: "s-2" }))
      assert.strictEqual(denied._tag, "PermissionDenied")
      if (denied._tag === "PermissionDenied") assert.strictEqual(denied.reason, "Limit")
    }))

  it.effect("fails to start when an RPC is not covered", () =>
    Effect.gen(function*() {
      const Unannotated = RpcGroup.make(Rpc.make("Ping", { success: Schema.String })).middleware(Authorize)
      assert.deepStrictEqual(PermissionRpc.validate(Unannotated, Authorize, Permissions), [
        "Ping has no required action; annotate it with an action or Permission.Public"
      ])
      const exit = yield* Effect.exit(
        Layer.build(PermissionRpc.layer(Authorize, Permissions, { group: Unannotated })).pipe(
          Effect.provide(Authorizer.layerDenyAll),
          Effect.scoped
        )
      )
      assert.isTrue(Exit.hasDies(exit))
    }))
})
