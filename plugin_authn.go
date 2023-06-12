//go:build plugin

package main

import (
	"net/http"
)

// Authn is an entrypoint that authenticates JWT via JWKs endpoints.
var Authn = NewJWTAuthenticator(http.DefaultClient)
