package main

# --- Policy: no package installs in the final stage -----------------------
# Why this exists: the final stage is what actually ships. Installing
# packages there instead of only in the builder stage grows the attack
# surface for no benefit — more OS packages means more potential CVEs and
# more to patch over time. For govault this is especially pointed: the
# final stage is distroless, where "no package manager present at all" is
# the whole point (see Phase 7's evidence: 0 vulnerabilities, 5 packages
# total). A package install showing up there would be a sign that
# minimal-final-stage property has quietly regressed — and on distroless
# specifically it would actually break the build (no apt/apk binary
# exists), but this rule catches the *intent* via static analysis before
# anyone wastes a build even attempting it.

# Match the install *subcommand* specifically (not just the tool name) so
# e.g. "apt-get update" alone doesn't double-fire alongside "apt-get
# install", and "apt-get" doesn't separately match a looser "apt" pattern.
install_patterns := {"apt-get install", "apt install", "apk add", "yum install", "dnf install", "microdnf install"}

deny contains msg if {
	instr := final_stage_instrs("run")[_]
	cmd_text := concat(" ", instr.Value)
	pattern := install_patterns[_]
	contains(cmd_text, pattern)
	msg := sprintf("final stage (stage %d) runs a package install ('%s' found in: %s) — only the builder stage should install packages", [max_stage, pattern, cmd_text])
}
