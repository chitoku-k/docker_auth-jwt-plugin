package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/glog"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var Authn api.Authenticator = NewJWTAuthenticator()

func NewJWTAuthenticator() *jwtAuthenticator {
	var jwkss []jwk.Set
	var jwksUsernameClaims []string

	for i := 0; ; i++ {
		jwksEndpoint := os.Getenv(fmt.Sprintf("DOCKER_AUTH_JWT_JWKS_%d_ENDPOINT", i))
		if jwksEndpoint == "" {
			break
		}
		jwksUsernameClaim := os.Getenv(fmt.Sprintf("DOCKER_AUTH_JWT_JWKS_%d_USERNAME_CLAIM", i))
		if jwksUsernameClaim == "" {
			break
		}

		cache := jwk.NewCache(context.Background())
		cache.Register(jwksEndpoint)

		jwkss = append(jwkss, jwk.NewCachedSet(cache, jwksEndpoint))
		jwksUsernameClaims = append(jwksUsernameClaims, jwksUsernameClaim)
	}

	if len(jwkss) == 0 {
		panic("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT and DOCKER_AUTH_JWT_JWKS_0_USER_CLAIM is not set")
	}

	aud := os.Getenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM")
	if aud == "" {
		panic("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM is not set")
	}

	return &jwtAuthenticator{
		jwkss:              jwkss,
		jwksUsernameClaims: jwksUsernameClaims,
		clientID:           aud,
	}
}

func createLabels(t jwt.Token) api.Labels {
	labels := api.Labels{}

	for it := t.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		k, v := pair.Key.(string), pair.Value

		switch v := v.(type) {
		case []string:
			labels[k] = v

		case string:
			if v == "" {
				labels[k] = []string{}
				continue
			}
			labels[k] = []string{v}

		case time.Time:
			labels[k] = []string{strconv.FormatInt(v.Unix(), 10)}
		}
	}

	return labels
}

type jwtAuthenticator struct {
	jwkss              []jwk.Set
	jwksUsernameClaims []string
	clientID           string
}

func (j *jwtAuthenticator) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	token := []byte(password)

	for i, jwks := range j.jwkss {
		t, err := jwt.Parse(token, jwt.WithKeySet(jwks), jwt.WithAudience(j.clientID), jwt.WithClaimValue(j.jwksUsernameClaims[i], user))
		if errors.Is(err, jwt.ErrInvalidJWT()) {
			return false, nil, api.NoMatch
		}
		if jwt.IsValidationError(err) {
			glog.Errorf("Failed to validate token at %d: %v", i, err)
			return false, nil, api.NoMatch
		}
		if err != nil {
			glog.V(3).Infof("Failed to validate token at %d: %v", i, err)
			continue
		}

		exp := t.Expiration().Sub(time.Now())
		glog.V(1).Infof("Validated JWT for %v (exp %d)", t.Subject(), int(exp.Seconds()))
		return true, createLabels(t), nil
	}

	return false, nil, api.NoMatch
}

func (j *jwtAuthenticator) Stop() {
}

func (j *jwtAuthenticator) Name() string {
	return "JWT"
}
