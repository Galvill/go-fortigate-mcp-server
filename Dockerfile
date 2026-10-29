# Builds the image from source: docker build -t fortigate-mcp .
# Release images are built by GoReleaser from Dockerfile.goreleaser.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/fortigate-mcp ./cmd/fortigate-mcp

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/fortigate-mcp /usr/local/bin/fortigate-mcp
USER nonroot:nonroot
# Used only with FORTIGATE_MCP_TRANSPORT=http and FORTIGATE_MCP_HTTP_ADDR=0.0.0.0:8080.
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/fortigate-mcp"]
