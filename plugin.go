package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/glog"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var Authn api.Authenticator = NewJWTAuthenticator()

func NewJWTAuthenticator() *jwtAuthenticator {
	aud := os.Getenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM")
	if aud == "" {
		panic("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM is not set")
	}

	var jwkProviders []jwkProvider
	for i := 0; ; i++ {
		endpoint := os.Getenv(fmt.Sprintf("DOCKER_AUTH_JWT_JWKS_%d_ENDPOINT", i))
		if endpoint == "" {
			break
		}
		usernameClaim := os.Getenv(fmt.Sprintf("DOCKER_AUTH_JWT_JWKS_%d_USERNAME_CLAIM", i))
		if usernameClaim == "" {
			break
		}
		usernamePrefix := os.Getenv(fmt.Sprintf("DOCKER_AUTH_JWT_JWKS_%d_USERNAME_PREFIX", i))
		if usernamePrefix == "" {
			break
		}

		cache := jwk.NewCache(context.Background())
		cache.Register(endpoint)

		jwkProviders = append(jwkProviders, jwkProvider{
			keySet:         jwk.NewCachedSet(cache, endpoint),
			usernameClaim:  usernameClaim,
			usernamePrefix: usernamePrefix,
			clientID:       aud,
		})
	}

	if len(jwkProviders) == 0 {
		panic("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT, DOCKER_AUTH_JWT_JWKS_0_USERNAME_CLAIM, and DOCKER_AUTH_JWT_JWKS_0_USERNAME_PREFIX is not set")
	}

	return &jwtAuthenticator{
		jwkProviders: jwkProviders,
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
	jwkProviders []jwkProvider
}

type jwkProvider struct {
	keySet         jwk.Set
	usernameClaim  string
	usernamePrefix string
	clientID       string
}

func (j *jwtAuthenticator) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	token := []byte(password)

	for i, jwkProvider := range j.jwkProviders {
		if !strings.HasPrefix(user, jwkProvider.usernamePrefix) {
			continue
		}

		usernameClaim := strings.TrimPrefix(user, jwkProvider.usernamePrefix)
		if usernameClaim == "" {
			continue
		}

		t, err := jwt.Parse(
			token,
			jwt.WithKeySet(jwkProvider.keySet),
			jwt.WithAudience(jwkProvider.clientID),
			jwt.WithClaimValue(jwkProvider.usernameClaim, usernameClaim),
		)
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
