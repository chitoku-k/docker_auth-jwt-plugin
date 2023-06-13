docker\_auth-jwt-plugin
=======================

[![][workflow-badge]][workflow-link]

Authentication plugin for [cesanta/docker\_auth] that verifies JWTs (JSON Web
Token) via JWKs endpoint.

## Installation

```sh
docker run \
    --env=DOCKER_AUTH_JWT_JWKS_0_ENDPOINT \
    --env=DOCKER_AUTH_JWT_JWKS_1_ENDPOINT \
    --env=DOCKER_AUTH_JWT_USERNAME \
    --env=DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM \
    --mount=type=bind,src=./config/auth_config.yml,dst=/config/auth_config.yml \
    ghcr.io/chitoku-k/docker_auth
```

## Usage

Configure docker\_auth as in the following:

```yaml
plugin_authn:
  plugin_path: /docker_auth/plugins/docker_auth-jwt-plugin.so
```

Start docker\_auth with the environment variable(s):

```sh
# JWKs endpoint(s) that is/are verified with (at least one endpoint is required)
export DOCKER_AUTH_JWT_JWKS_0_ENDPOINT=https://www.googleapis.com/oauth2/v3/certs
export DOCKER_AUTH_JWT_JWKS_1_ENDPOINT=https://token.actions.githubusercontent.com/.well-known/jwks
# ...

# Fixed username for `docker login` (required; username that contains `:` does not work due to BASIC Auth)
export DOCKER_AUTH_JWT_USERNAME=oauth2accesstoken

# Lowercase labels after authentication is successful (optional; useful for ACL)
export DOCKER_AUTH_JWT_LOWERCASE_LABELS=false

# JWT "aud" claim whose value must be verified against (required)
export DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM=your-client-id
```

Execute `docker login` with the fixed username and the token as a password:

```sh
docker login \
    registry.example.com \
    --username='oauth2accesstoken' \
    --password-stdin <<< 'token'
```

[cesanta/docker\_auth]: https://github.com/cesanta/docker_auth
[workflow-link]:        https://github.com/chitoku-k/docker_auth-jwt-plugin/actions?query=branch:master
[workflow-badge]:       https://img.shields.io/github/actions/workflow/status/chitoku-k/docker_auth-jwt-plugin/ci.yml?branch=master&style=flat-square&logo=github
