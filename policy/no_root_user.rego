package main

# --- Policy: the final stage must not run as root ------------------------
# Why this exists: if the app is ever compromised (RCE, path traversal, a
# vulnerable dependency), a process running as root has the largest
# possible blast radius inside the container. Requires an explicit USER
# instruction in the final stage, and its value must not be root/UID 0.
#
# Overlap note: Phase 7 already checks this on the BUILT image (`docker
# inspect` on the actual image config). This rule checks the same property
# at the Dockerfile-source layer instead — it catches the mistake before
# anyone even runs `docker build`, and keeps failing even if Phase 7's
# check were ever accidentally removed. Same property, different, cheaper,
# earlier layer — intentional defense in depth, not the point of this
# phase's "distinct value" story (see no_add.rego for that).

deny contains msg if {
	count(final_stage_instrs("user")) == 0
	msg := sprintf("no USER instruction in final stage (stage %d) — container would run as root by default", [max_stage])
}

deny contains msg if {
	users := final_stage_instrs("user")
	count(users) > 0
	last_user := users[count(users) - 1]
	value := last_user.Value[0]
	is_root_user(value)
	msg := sprintf("final stage USER is '%s' — must not run as root/UID 0", [value])
}

is_root_user(v) if { v == "0" }

is_root_user(v) if { v == "root" }

is_root_user(v) if { startswith(v, "0:") }

is_root_user(v) if { startswith(v, "root:") }
