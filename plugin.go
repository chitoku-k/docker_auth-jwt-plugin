package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/glog"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Ensure that *jwtAuthenticator implements api.Authenticator, for plugin.Symbol is a pointer.
var _ api.Authenticator = (*jwtAuthenticator)(nil)

type jwtAuthenticator struct {
	jwkProviders []jwkProvider
	username     string

	lowercaseLabels bool
}

type jwkProvider struct {
	keySet   jwk.Set
	clientID string
}

func NewJWTAuthenticator(httpClient *http.Client) jwtAuthenticator {
	username := os.Getenv("DOCKER_AUTH_JWT_USERNAME")
	if username == "" {
		panic("DOCKER_AUTH_JWT_USERNAME is not set")
	}

	var lowercaseLabels bool
	lowercaseLabelsEnv := os.Getenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS")
	if lowercaseLabelsEnv != "" {
		var err error
		lowercaseLabels, err = strconv.ParseBool(lowercaseLabelsEnv)
		if err != nil {
			panic("DOCKER_AUTH_JWT_LOWERCASE_LABELS is invalid")
		}
	}

	var jwkProviders []jwkProvider
	for i := 0; ; i++ {
		endpoint := os.Getenv(fmt.Sprintf("DOCKER_AUTH_JWT_JWKS_%d_ENDPOINT", i))
		if endpoint == "" {
			break
		}

		aud := os.Getenv(fmt.Sprintf("DOCKER_AUTH_JWT_JWKS_%d_REQUIRED_AUD_CLAIM", i))
		if aud == "" {
			break
		}

		jwkHTTPClient := httpClient
		caPath := os.Getenv(fmt.Sprintf("DOCKER_AUTH_JWT_JWKS_%d_CA_PATH", i))
		if caPath != "" {
			var err error
			jwkHTTPClient, err = httpClientWithRootCA(jwkHTTPClient, caPath)
			if err != nil {
				panic(fmt.Sprintf("DOCKER_AUTH_JWT_JWKS_%d_CA_PATH cannot be configured: %v", i, err))
			}
		}

		cache := jwk.NewCache(context.Background())
		cache.Register(endpoint, jwk.WithHTTPClient(jwkHTTPClient))

		jwkProviders = append(jwkProviders, jwkProvider{
			keySet:   jwk.NewCachedSet(cache, endpoint),
			clientID: aud,
		})
	}

	if len(jwkProviders) == 0 {
		panic("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT is not set")
	}

	return jwtAuthenticator{
		jwkProviders:    jwkProviders,
		username:        username,
		lowercaseLabels: lowercaseLabels,
	}
}

func lowercaseLabels(labels api.Labels) api.Labels {
	for _, label := range labels {
		for k, v := range label {
			label[k] = strings.ToLower(v)
		}
	}
	return labels
}

func (j *jwtAuthenticator) createLabels(t jwt.Token) api.Labels {
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

	if j.lowercaseLabels {
		return lowercaseLabels(labels)
	}

	return labels
}

func (j *jwtAuthenticator) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	token := []byte(password)
	if user != j.username {
		return false, nil, api.NoMatch
	}

	for i, jwkProvider := range j.jwkProviders {
		t, err := jwt.Parse(
			token,
			jwt.WithKeySet(jwkProvider.keySet),
			jwt.WithAudience(jwkProvider.clientID),
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

		exp := time.Until(t.Expiration())
		glog.V(1).Infof("Validated JWT for %v (exp %d)", t.Subject(), int(exp.Seconds()))
		return true, j.createLabels(t), nil
	}

	return false, nil, api.NoMatch
}

func (j *jwtAuthenticator) Stop() {
}

func (j *jwtAuthenticator) Name() string {
	return "JWT"
}
