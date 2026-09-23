FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/mock-keycloak ./cmd/mock-keycloak

# alpine rather than scratch/distroless: busybox wget is what a compose
# healthcheck calls.
FROM alpine:3.24
RUN adduser -D -H -u 10001 mock-keycloak \
 && mkdir /data \
 && chown mock-keycloak:mock-keycloak /data
COPY --from=build /out/mock-keycloak /usr/local/bin/mock-keycloak
USER mock-keycloak
# A relative signingKeyFile (the default is jwt-signing.key) lands here. The
# key file is created on first start, but its directory is not.
WORKDIR /data
ENV CONFIG_PATH=/config/config.json
EXPOSE 10101
ENTRYPOINT ["/usr/local/bin/mock-keycloak"]
