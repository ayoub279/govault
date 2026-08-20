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
# distroless/static: no shell, no package manager, no libc — just CA certs,
# /etc/passwd, tzdata. Smallest sensible base for a static Go binary and the
# smallest attack surface for a security-focused service.
FROM gcr.io/distroless/static-debian12:nonroot

# The :nonroot variant ships a "nonroot" user with UID/GID 65532. We set it
# explicitly (rather than relying on the tag's default) so the runtime user is
# auditable and won't silently change if the base image is swapped.
USER 65532:65532

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
