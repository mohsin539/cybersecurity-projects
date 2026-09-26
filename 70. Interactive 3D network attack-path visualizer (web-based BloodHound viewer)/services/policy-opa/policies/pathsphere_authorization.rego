package pathsphere.authorization

import rego.v1

# PathSphere 3D authorization policy (ABAC).
# Loaded by the Policy service as `/v1/data/pathsphere/authorization/allow`.

# --- Attribute-based access control ---

# Allow when the requestor role + sensitivity permit the action.
default allow := false

allowed_roles[role] if {
    role := input.role
}

# Role capabilities
role_capabilities := {
    "Admin":       ["graph.read", "graph.write", "report.create", "report.sign", "ledger.read", "ingest"],
    "Analyst":     ["graph.read", "path.compute", "report.create", "report.sign", "ingest"],
    "Auditor":     ["graph.read", "ledger.read", "report.view"],
    "Viewer":      ["graph.read"],
}

has_capability(action) if {
    action in role_capabilities[input.role]
}

tenant_match if input.tenant_id in input.tenant_ids

sensitivity_allowed if input.sensitivity in {"public", "internal"} and input.role in {"Analyst", "Admin", "Auditor"}
sensitivity_allowed if input.sensitivity == "confidential" and input.role == "Admin"

allow if {
    has_capability(input.action)
    tenant_match
    sensitivity_allowed
}

# --- Deny always for restricted resources unless Admin + explicit bypass ---
deny["restricted_without_admin"] if {
    input.sensitivity == "restricted"
    input.role != "Admin"
}

# Report signing requires approving auditor/owner (4-eyes) unless system.
allow if {
    input.action in {"report.create", "report.sign"}
    input.approver_required == false
}

# Permitted-node-scope: requestor may only see objects within owned OUs.
object_in_scope if {
    count(input.ous) == 0
} else if {
    input.object_ou in input.ous
}

allow if {
    has_capability(input.action)
    tenant_match
    object_in_scope
}