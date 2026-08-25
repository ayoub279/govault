package main

# Shared helpers used by the policy files in this directory. Conftest's
# Dockerfile parser gives Rego one flat array of instruction objects, each
# with a lowercase Cmd ("from", "run", "copy", "add", "user", "env", "arg",
# "healthcheck", ...), a 0-indexed Stage (incremented per FROM), Flags, and
# Value (shape depends on Cmd).

# The final build stage — multi-stage Dockerfiles are 0-indexed per FROM.
# Rules that only care about the shippable final image (not intermediate
# builder stages, e.g. "must run as non-root") key off this so they don't
# false-positive on a builder stage that legitimately runs as root.
max_stage := m if {
	stages := [s | s := input[_].Stage]
	m := max(stages)
}

# All instructions with the given Cmd (lowercase) that belong to the final
# stage.
final_stage_instrs(cmd) := [i |
	i := input[_]
	i.Cmd == cmd
	i.Stage == max_stage
]
