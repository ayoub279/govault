package main

# --- Policy: use COPY, not ADD -------------------------------------------
# Why this exists: ADD has "magic" behavior COPY does not — it auto-
# extracts local tar/gzip archives and can fetch from remote URLs at build
# time. Both are easy to misuse: silent extraction of an archive nobody
# meant to unpack, or a network fetch with no integrity checking baked
# into the instruction itself (unlike a pinned base image or a checked-in,
# reviewed file). COPY is the explicit, predictable "put this file in the
# image" instruction and is Docker's own recommended default; ADD should
# only appear where its extra behavior is genuinely needed, which nothing
# in this project's Dockerfile does.
#
# This is the rule this phase is really about: none of the earlier tools
# (Gitleaks, Semgrep, Trivy in either mode, govulncheck) parse Dockerfile
# *instruction semantics* at all — Gitleaks does regex/entropy over raw
# bytes, Semgrep here only runs Go-source rule packs, and Trivy's misconfig
# scanning is either scoped off (Phase 6, vuln-only) or, in image mode
# (Phase 7), only looks for IaC files accidentally baked into a layer, not
# the Dockerfile that built the image. A COPY silently swapped for ADD
# changes zero bytes in the resulting image, trips no CVE, and contains no
# secret — every scanner in this pipeline would report it clean. Only a
# tool that reads Dockerfile instructions as structured data can catch it.
#
# Proven live: on the throwaway verification branch, this exact change
# (COPY . . -> ADD . .) left Build & Test, Docker Build & Scan (including
# the non-root check), Secrets Scan, SAST Scan, and Dependency Scan all
# green — only this policy caught it.

deny contains msg if {
	instr := input[_]
	instr.Cmd == "add"
	msg := sprintf("stage %d uses ADD (%v) — use COPY instead unless remote-fetch/archive-extraction is genuinely required", [instr.Stage, instr.Value])
}
