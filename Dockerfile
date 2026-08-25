# syntax=docker/dockerfile:1

##############################
# Build stage
##############################
FROM golang:1.26-bookworm AS build

WORKDIR /src

# Download modules first so this layer is cached unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source.
COPY . .

# Static, CGO-free, stripped binaries. -trimpath keeps build paths out of the
# binary. Everything used (pgx, bcrypt, aes, paseto) is pure Go, so no libc is
# needed and the result runs on a scratch/distroless-static base.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/govault     ./cmd/api && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/migrate     ./cmd/migrate && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/healthcheck ./cmd/healthcheck

##############################
# Final stage
##############################
# TEMP (test/imagescan-verify only): deliberately swapped to an old, EOL,
# root-by-default base image with real HIGH/CRITICAL CVEs (verified locally:
# 30 vulnerabilities, 28 HIGH + 2 CRITICAL) and the explicit USER line
# removed, to verify the Phase 7 image-scan CI gate actually catches both a
# real OS-vuln finding and a real "runs as root" finding. Reverted to
# distroless/nonroot before this branch is done being used; never lands on
# main.
FROM debian:9

WORKDIR /app

# Application binary, the migration runner, and the health probe.
COPY --from=build /out/govault     /app/govault
COPY --from=build /out/migrate     /app/migrate
COPY --from=build /out/healthcheck /app/healthcheck

# Plain-SQL migrations, read by /app/migrate (defaults to ./migrations).
COPY --from=build /src/migrations  /app/migrations

# Matches PORT in .env.example (documentation/tooling hint; does not publish).
EXPOSE 8080

# distroless has no shell, so use the exec-form CMD with our compiled probe.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/healthcheck"]

ENTRYPOINT ["/app/govault"]
