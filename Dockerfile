# syntax = docker/dockerfile:experimental
FROM golang:1.20.5 AS build
WORKDIR /usr/src
COPY go.mod go.sum /usr/src/
RUN --mount=type=cache,target=/go \
    go mod download
COPY . /usr/src/
RUN --mount=type=cache,target=/go \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -buildmode=plugin -ldflags='-s -w'

FROM cesanta/docker_auth:1.11.0
COPY --from=build /usr/src/docker_auth-jwt-plugin.so /docker_auth/plugins/
