package main

# --- Policy: the final stage must define a HEALTHCHECK -------------------
# Why this exists: without a HEALTHCHECK, `docker ps` and orchestrators
# have no signal that the container process is actually alive and serving
# traffic, as opposed to merely running. A hung or deadlocked process looks
# identical to a healthy one without this. (The final stage here is
# distroless with no shell, so the healthcheck has to be the compiled probe
# binary in cmd/healthcheck rather than a shell command — that specific
# requirement is enforced by the Dockerfile working at build time at all,
# not by this policy; this policy only guarantees a HEALTHCHECK exists.)

deny contains msg if {
	count(final_stage_instrs("healthcheck")) == 0
	msg := sprintf("no HEALTHCHECK instruction in final stage (stage %d)", [max_stage])
}
