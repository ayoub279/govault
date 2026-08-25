package main

# --- Policy: no hardcoded-looking secrets in ENV or ARG defaults ---------
# Why this exists: this is a backstop, not a replacement for Gitleaks
# (Phase 4), which already scans the whole repo — including this
# Dockerfile — with a proper entropy+pattern secret-detection engine and
# its own regularly-updated ruleset. This rule exists so a Dockerfile
# change that introduces an obviously secret-shaped ENV/ARG value fails
# fast at the Dockerfile-policy layer too, with zero dependency on
# Gitleaks' ruleset staying in sync with what a Dockerfile author might
# type — genuine defense in depth for exactly the class of mistake this
# project cares most about (it's a secrets manager).

secret_keywords := {
	"password", "passwd", "secret", "api_key", "apikey",
	"access_key", "private_key", "token",
}

deny contains msg if {
	instr := input[_]
	instr.Cmd == "env"
	kv := lower(concat(" ", instr.Value))
	keyword := secret_keywords[_]
	contains(kv, keyword)
	msg := sprintf("stage %d ENV looks like it hardcodes a secret (matched '%s'): %v — inject secrets at deploy time, never as a literal value in the Dockerfile", [instr.Stage, keyword, instr.Value])
}

deny contains msg if {
	instr := input[_]
	instr.Cmd == "arg"
	contains(instr.Value[0], "=") # only ARGs with a baked-in default — a bare "ARG NAME" supplies no value here
	kv := lower(instr.Value[0])
	keyword := secret_keywords[_]
	contains(kv, keyword)
	msg := sprintf("stage %d ARG looks like it hardcodes a secret default (matched '%s'): %v — ARGs with secret-shaped names must not ship a default value", [instr.Stage, keyword, instr.Value])
}
