# syntax = docker/dockerfile:1
FROM golang:1.21.2 AS build
WORKDIR /usr/src
COPY . /usr/src/
RUN --mount=type=cache,target=/go \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -buildmode=plugin -tags=plugin -ldflags='-s -w'

FROM golang:1.21.2 AS core
WORKDIR /usr/src/docker_auth/auth_server
COPY . /usr/src/
ARG DOCKER_AUTH_VERSION=1.11.0
RUN --mount=type=cache,target=/go \
    --mount=type=cache,target=/root/.cache/go-build \
    VERSION=$DOCKER_AUTH_VERSION && \
    BUILD_ID=$(date +%Y%m%d-%H%M%S)/$VERSION@$(git rev-parse --short=8 HEAD) && \
    go build -ldflags="-X 'main.Version=${VERSION}' -X 'main.BuildID=${BUILD_ID}'"

FROM scratch
COPY --from=core /usr/src/docker_auth/auth_server/auth_server /docker_auth/
COPY --from=build /usr/src/docker_auth-jwt-plugin.so /docker_auth/plugins/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /lib/x86_64-linux-gnu/ld-* /lib/x86_64-linux-gnu/
COPY --from=build /lib/x86_64-linux-gnu/libc.* /lib/x86_64-linux-gnu/libc-* /lib/x86_64-linux-gnu/
COPY --from=build /lib/x86_64-linux-gnu/libdl.* /lib/x86_64-linux-gnu/libdl-* /lib/x86_64-linux-gnu/
COPY --from=build /lib/x86_64-linux-gnu/libpthread.* /lib/x86_64-linux-gnu/libpthread-* /lib/x86_64-linux-gnu/
COPY --from=build /lib/x86_64-linux-gnu/libresolv.* /lib/x86_64-linux-gnu/libresolv-* /lib/x86_64-linux-gnu/
COPY --from=build /lib64/ld-linux-x86-64.so* /lib64/
RUN --mount=from=build,source=/bin,target=/bin \
    --mount=from=build,source=/lib,target=/lib \
    --mount=from=build,source=/usr,target=/usr \
    mkdir --mode=1777 /tmp
ENTRYPOINT ["/docker_auth/auth_server"]
CMD ["/config/auth_config.yml"]
EXPOSE 5001
