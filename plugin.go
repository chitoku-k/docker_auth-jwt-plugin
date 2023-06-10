package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var Authn api.Authenticator = NewJWTAuthenticator()

func NewJWTAuthenticator() *jwtAuthenticator {
	var jwkss []jwk.Set
	for i := 0; ; i++ {
		jwksEndpoint := os.Getenv(fmt.Sprintf("DOCKER_AUTH_JWT_JWKS_ENDPOINT_%d", i))
		if jwksEndpoint == "" {
			break
		}

		cache := jwk.NewCache(context.Background())
		cache.Register(jwksEndpoint)
		jwkss = append(jwkss, jwk.NewCachedSet(cache, jwksEndpoint))
	}

	if len(jwkss) == 0 {
		panic("DOCKER_AUTH_JWT_JWKS_ENDPOINT_0 is not set")
	}

	return &jwtAuthenticator{
		jwkss: jwkss,
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
	jwkss []jwk.Set
}

func (j *jwtAuthenticator) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	var errs []error
	for i, jwks := range j.jwkss {
		t, err := jwt.Parse([]byte(password), jwt.WithKeySet(jwks))
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse token at %d: %w", i, err))
			continue
		}
		return true, createLabels(t), nil
	}

	return false, nil, errors.Join(errs...)
}

func (j *jwtAuthenticator) Stop() {
}

func (j *jwtAuthenticator) Name() string {
	return "JWT"
}
