import { Context, Schema } from "effect"
import { Condition, Permission, Principal } from "effect/permission"

export class Unit extends Schema.Class<Unit>("Unit")({
  id: Schema.String,
  hospitalId: Schema.String,
  name: Schema.String
}) {}

export class SwapRequest extends Schema.Class<SwapRequest>("SwapRequest")({
  id: Schema.String,
  unitId: Schema.String,
  requesterId: Schema.String,
  recipientId: Schema.String,
  status: Schema.Literals(["pending", "accepted", "approved"])
}) {}

export interface Member {
  readonly homeHospitalId: string
  readonly isSuperAdmin: boolean
  readonly managesUnits: boolean
  readonly managesSwaps: boolean
}

export class CurrentPrincipal extends Context.Service<
  CurrentPrincipal,
  Principal.Principal<Member>
>()("test/permission/CurrentPrincipal") {}

export const UnitMembership = Condition.relation<string, string>("unit:member")

export const UnitRules = Permission.rules(CurrentPrincipal, Unit)
  .action("units:read", {
    filter: ({ principal, resource: unit }) =>
      Condition.or(
        principal.attributes.isSuperAdmin,
        Condition.eq(unit.hospitalId, principal.attributes.homeHospitalId),
        Condition.related(UnitMembership, principal.subject.id, unit.id)
      )
  })
  .action("units:update", {
    filter: ({ principal, allowed }) => Condition.and(allowed("units:read"), principal.attributes.managesUnits),
    check: ({ allowed }) => allowed("units:read")
  })

export const SwapRules = Permission.rules(CurrentPrincipal, SwapRequest)
  .action("swaps:read", {
    filter: ({ principal, resource: swap }) =>
      Condition.or(
        Condition.eq(swap.requesterId, principal.subject.id),
        Condition.eq(swap.recipientId, principal.subject.id),
        Condition.and(
          principal.attributes.managesSwaps,
          Condition.related(UnitMembership, principal.subject.id, swap.unitId)
        )
      )
  })
  .create("swaps:create", {
    set: ({ principal }) => ({ requesterId: principal.subject.id, status: "pending" }),
    check: ({ principal, resource: swap }) => Condition.related(UnitMembership, principal.subject.id, swap.unitId)
  })
  .action("swaps:accept", {
    filter: ({ principal, resource: swap }) =>
      Condition.and(Condition.eq(swap.recipientId, principal.subject.id), Condition.eq(swap.status, "pending"))
  })
  .action("swaps:approve", {
    filter: ({ principal, resource: swap }) =>
      Condition.and(
        Condition.eq(swap.status, "accepted"),
        Condition.notEq(swap.requesterId, principal.subject.id),
        principal.attributes.managesSwaps,
        Condition.related(UnitMembership, principal.subject.id, swap.unitId)
      ),
    // Support staff can look while impersonating, but not approve
    forbid: ({ principal }) => Condition.isNotNull(principal.actor)
  })

export const Permissions = Permission.make(CurrentPrincipal, {
  rules: [UnitRules, SwapRules],
  aliases: {
    "swaps:respond": ["swaps:read", "swaps:accept"]
  }
})

const member = (overrides: Partial<Member>): Member => ({
  homeHospitalId: "h-1",
  isSuperAdmin: false,
  managesUnits: false,
  managesSwaps: false,
  ...overrides
})

export const nurse = Principal.make({ subject: "p-nurse", attributes: member({}) })
export const otherNurse = Principal.make({ subject: "p-other", attributes: member({ homeHospitalId: "h-2" }) })
export const manager = Principal.make({
  subject: "p-manager",
  attributes: member({ managesUnits: true, managesSwaps: true })
})
export const admin = Principal.make({
  subject: "p-admin",
  attributes: member({ homeHospitalId: "h-9", isSuperAdmin: true })
})

export const units = [
  new Unit({ id: "u-1", hospitalId: "h-1", name: "ICU" }),
  new Unit({ id: "u-2", hospitalId: "h-2", name: "Cardiology" }),
  new Unit({ id: "u-3", hospitalId: "h-3", name: "Oncology" })
]

export const memberships = [
  UnitMembership.of("p-nurse", "u-2"),
  UnitMembership.of("p-manager", "u-1"),
  UnitMembership.of("p-other", "u-1")
]

export const swap = (overrides: Partial<SwapRequest>): SwapRequest =>
  new SwapRequest({
    id: "s-1",
    unitId: "u-1",
    requesterId: "p-other",
    recipientId: "p-nurse",
    status: "pending",
    ...overrides
  })
