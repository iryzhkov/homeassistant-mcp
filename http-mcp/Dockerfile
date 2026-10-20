# Supply an operator-reviewed immutable Go image reference with --build-arg.
ARG GO_IMAGE
FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -o /out/ha-mcp ./cmd/ha-mcp

FROM scratch
COPY --from=build --chmod=0555 /out/ha-mcp /usr/local/bin/ha-mcp
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ha-mcp"]
CMD ["-config", "/etc/ha-mcp/config.json"]
