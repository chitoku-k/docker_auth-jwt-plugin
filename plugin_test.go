package main_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
	. "github.com/chitoku-k/docker_auth-jwt-plugin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "JWT Plugin Suite")
}

// RFC 7517 - JSON Web Key (JWK)
// URL: https://datatracker.ietf.org/doc/html/rfc7517#section-4

// RFC 7518 - JSON Web Algorithms (JWA)
// URL: https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1

var _ = Describe("Authn", func() {
	var (
		server    *ghttp.Server
		endpoint1 string
		endpoint2 string
		caFile    *os.File

		authn api.Authenticator
		token []byte

		signingKey1 *rsa.PrivateKey
		signingKey2 *rsa.PrivateKey
		signingKey3 *rsa.PrivateKey

		keyID1 string
		keyID2 string
		keyID3 string
	)

	BeforeEach(func() {
		var err error
		server = ghttp.NewTLSServer()

		ca := server.HTTPTestServer.Certificate()
		caFile, err = os.CreateTemp("", "docker_auth-jwt-plugin-test-*.crt")
		Expect(err).NotTo(HaveOccurred())

		err = pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
		Expect(err).NotTo(HaveOccurred())

		endpoint1, err = url.JoinPath(server.URL(), ".well-known/jwks")
		Expect(err).NotTo(HaveOccurred())

		endpoint2, err = url.JoinPath(server.URL(), "v2/jwks")
		Expect(err).NotTo(HaveOccurred())

		signingKey1, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		signingKey2, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		signingKey3, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		keyID1 = "test-key"
		n1 := signingKey1.N
		e1 := big.NewInt(int64(signingKey1.E))

		keyID2 = "test-key-2"
		n2 := signingKey2.N
		e2 := big.NewInt(int64(signingKey2.E))

		keyID3 = "test-key-3"

		server.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest(http.MethodGet, "/.well-known/jwks"),
				ghttp.RespondWithJSONEncoded(http.StatusOK, map[string]any{
					"keys": []map[string]any{
						{
							jwk.KeyTypeKey:   jwa.RSA,
							jwk.KeyUsageKey:  jwk.ForSignature,
							jwk.AlgorithmKey: jwa.RS256,
							jwk.KeyIDKey:     keyID1,
							jwk.RSANKey:      base64.URLEncoding.EncodeToString(n1.Bytes()),
							jwk.RSAEKey:      base64.URLEncoding.EncodeToString(e1.Bytes()),
						},
					},
				}),
			),
			ghttp.CombineHandlers(
				ghttp.VerifyRequest(http.MethodGet, "/v2/jwks"),
				ghttp.RespondWithJSONEncoded(http.StatusOK, map[string]any{
					"keys": []map[string]any{
						{
							jwk.KeyTypeKey:   jwa.RSA,
							jwk.KeyUsageKey:  jwk.ForSignature,
							jwk.AlgorithmKey: jwa.RS256,
							jwk.KeyIDKey:     keyID2,
							jwk.RSANKey:      base64.URLEncoding.EncodeToString(n2.Bytes()),
							jwk.RSAEKey:      base64.URLEncoding.EncodeToString(e2.Bytes()),
						},
					},
				}),
			),
		)
	})

	AfterEach(func() {
		server.Close()

		caFile.Close()
		os.Remove(caFile.Name())
	})

	Context("NewJWTAuthenticator()", func() {
		Context("when any of configurations are not set", func() {
			Context("when DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM is not set", func() {
				BeforeEach(func() {
					os.Unsetenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM")
					os.Unsetenv("DOCKER_AUTH_JWT_USERNAME")
					os.Unsetenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH")
				})

				It("panics", func() {
					Expect(func() {
						NewJWTAuthenticator(http.DefaultClient)
					}).To(PanicWith("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM is not set"))
				})
			})

			Context("when DOCKER_AUTH_JWT_USERNAME is not set", func() {
				BeforeEach(func() {
					os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
					os.Unsetenv("DOCKER_AUTH_JWT_USERNAME")
					os.Unsetenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH")
				})

				It("panics", func() {
					Expect(func() {
						NewJWTAuthenticator(http.DefaultClient)
					}).To(PanicWith("DOCKER_AUTH_JWT_USERNAME is not set"))
				})
			})

			Context("when DOCKER_AUTH_JWT_JWKS_0_ENDPOINT is not set", func() {
				BeforeEach(func() {
					os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
					os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
					os.Unsetenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH")
					os.Unsetenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH")
				})

				It("panics", func() {
					Expect(func() {
						NewJWTAuthenticator(http.DefaultClient)
					}).To(PanicWith("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT is not set"))
				})
			})
		})

		Context("when DOCKER_AUTH_JWT_LOWERCASE_LABELS is invalid", func() {
			BeforeEach(func() {
				os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
				os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
				os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "invalid")
				os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
				os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
				os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
				os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())
			})

			It("panics", func() {
				Expect(func() {
					NewJWTAuthenticator(http.DefaultClient)
				}).To(PanicWith("DOCKER_AUTH_JWT_LOWERCASE_LABELS is invalid"))
			})
		})

		Context("when DOCKER_AUTH_JWT_JWKS_0_CA_PATH is invalid", func() {
			BeforeEach(func() {
				os.Remove(caFile.Name())

				os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
				os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
				os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "false")
				os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
				os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
				os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
				os.Unsetenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH")
			})

			It("panics", func() {
				Expect(func() {
					NewJWTAuthenticator(http.DefaultClient)
				}).To(PanicWith(HavePrefix("DOCKER_AUTH_JWT_JWKS_0_CA_PATH cannot be configured:")))
			})
		})

		Context("when all of configurations are set", func() {
			Context("when Transport is not set", func() {
				BeforeEach(func() {
					os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
					os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
					os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "false")
					os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
					os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
					os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
					os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())
				})

				It("returns authenticator", func() {
					Expect(func() {
						NewJWTAuthenticator(http.DefaultClient)
					}).NotTo(Panic())
				})
			})

			Context("when Transport is set", func() {
				var (
					proxyURL *url.URL
				)

				BeforeEach(func() {
					var err error
					proxyURL, err = url.Parse("http://proxy.example.com:8080")
					Expect(err).NotTo(HaveOccurred())

					os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
					os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
					os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "false")
					os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
					os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
					os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
					os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())
				})

				It("returns authenticator", func() {
					Expect(func() {
						NewJWTAuthenticator(&http.Client{
							Transport: &http.Transport{
								Proxy:        http.ProxyURL(proxyURL),
								TLSNextProto: map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
							},
						})
					}).NotTo(Panic())
				})
			})
		})
	})

	Context("Authenticate()", func() {
		Context("when username does not match", func() {
			BeforeEach(func() {
				os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
				os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
				os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "false")
				os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
				os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
				os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
				os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())

				plugin := NewJWTAuthenticator(http.DefaultClient)
				authn = &plugin
			})

			It("returns api.NoMatch error", func() {
				actualResult, actualLabels, err := authn.Authenticate("username", api.PasswordString("password"))
				Expect(actualResult).To(BeFalse())
				Expect(actualLabels).To(BeNil())
				Expect(err).To(Equal(api.NoMatch))
			})
		})

		Context("when username matches", func() {
			Context("when token is in invalid format", func() {
				BeforeEach(func() {
					os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
					os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
					os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "false")
					os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
					os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
					os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
					os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())

					plugin := NewJWTAuthenticator(http.DefaultClient)
					authn = &plugin
				})

				It("returns api.NoMatch error", func() {
					actualResult, actualLabels, err := authn.Authenticate("oauth2accesstoken", api.PasswordString("password"))
					Expect(actualResult).To(BeFalse())
					Expect(actualLabels).To(BeNil())
					Expect(err).To(Equal(api.NoMatch))
				})
			})

			Context("when token does not have required claim", func() {
				BeforeEach(func() {
					os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
					os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
					os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "false")
					os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
					os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
					os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
					os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())

					plugin := NewJWTAuthenticator(http.DefaultClient)
					authn = &plugin

					jwttoken, err := jwt.NewBuilder().
						Issuer("test-issuer").
						Audience([]string{"example.net"}).
						Subject("test-user").
						IssuedAt(time.Now()).
						Expiration(time.Now().Add(5*time.Minute)).
						Claim("test-claim-1", "test-value-1").
						Claim("test-claim-2", "TEST-VALUE-2").
						Claim("test-claim-3", "").
						Build()
					Expect(err).NotTo(HaveOccurred())

					headers := jws.NewHeaders()
					headers.Set(jws.KeyIDKey, keyID1)

					token, err = jwt.Sign(jwttoken, jwt.WithKey(jwa.RS256, signingKey1, jws.WithProtectedHeaders(headers)))
					Expect(err).NotTo(HaveOccurred())
				})

				AfterEach(func() {
					Expect(server.ReceivedRequests()).To(HaveLen(1))
				})

				It("returns api.NoMatch error", func() {
					actualResult, actualLabels, err := authn.Authenticate("oauth2accesstoken", api.PasswordString(token))
					Expect(actualResult).To(BeFalse())
					Expect(actualLabels).To(BeNil())
					Expect(err).To(Equal(api.NoMatch))
				})
			})

			Context("when token cannot be validated", func() {
				BeforeEach(func() {
					os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
					os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
					os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "false")
					os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
					os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
					os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
					os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())

					plugin := NewJWTAuthenticator(http.DefaultClient)
					authn = &plugin

					jwttoken, err := jwt.NewBuilder().
						Issuer("test-issuer").
						Audience([]string{"example.net"}).
						Subject("test-user").
						IssuedAt(time.Now()).
						Expiration(time.Now().Add(5*time.Minute)).
						Claim("test-claim-1", "test-value-1").
						Claim("test-claim-2", "TEST-VALUE-2").
						Claim("test-claim-3", "").
						Build()
					Expect(err).NotTo(HaveOccurred())

					headers := jws.NewHeaders()
					headers.Set(jws.KeyIDKey, keyID3)

					token, err = jwt.Sign(jwttoken, jwt.WithKey(jwa.RS256, signingKey3, jws.WithProtectedHeaders(headers)))
					Expect(err).NotTo(HaveOccurred())
				})

				AfterEach(func() {
					Expect(server.ReceivedRequests()).To(HaveLen(2))
				})

				It("returns api.NoMatch error", func() {
					actualResult, actualLabels, err := authn.Authenticate("oauth2accesstoken", api.PasswordString(token))
					Expect(actualResult).To(BeFalse())
					Expect(actualLabels).To(BeNil())
					Expect(err).To(Equal(api.NoMatch))
				})
			})

			Context("when token is valid", func() {
				Context("when DOCKER_AUTH_JWT_LOWERCASE_LABELS is disabled", func() {
					BeforeEach(func() {
						os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
						os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
						os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "false")
						os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
						os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
						os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
						os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())

						plugin := NewJWTAuthenticator(http.DefaultClient)
						authn = &plugin

						jwttoken, err := jwt.NewBuilder().
							Issuer("test-issuer").
							Audience([]string{"example.com"}).
							Subject("test-user").
							IssuedAt(time.Now()).
							Expiration(time.Now().Add(5*time.Minute)).
							Claim("test-claim-1", "test-value-1").
							Claim("test-claim-2", "TEST-VALUE-2").
							Claim("test-claim-3", "").
							Build()
						Expect(err).NotTo(HaveOccurred())

						headers := jws.NewHeaders()
						headers.Set(jws.KeyIDKey, keyID1)

						token, err = jwt.Sign(jwttoken, jwt.WithKey(jwa.RS256, signingKey1, jws.WithProtectedHeaders(headers)))
						Expect(err).NotTo(HaveOccurred())
					})

					AfterEach(func() {
						Expect(server.ReceivedRequests()).To(HaveLen(1))
					})

					It("returns true and labels", func() {
						actualResult, actualLabels, err := authn.Authenticate("oauth2accesstoken", api.PasswordString(token))
						Expect(actualResult).To(BeTrue())
						Expect(actualLabels).To(HaveKeyWithValue("iss", []string{"test-issuer"}))
						Expect(actualLabels).To(HaveKeyWithValue("sub", []string{"test-user"}))
						Expect(actualLabels).To(HaveKeyWithValue("aud", []string{"example.com"}))
						Expect(actualLabels).To(HaveKeyWithValue("test-claim-1", []string{"test-value-1"}))
						Expect(actualLabels).To(HaveKeyWithValue("test-claim-2", []string{"TEST-VALUE-2"}))
						Expect(actualLabels).To(HaveKeyWithValue("test-claim-3", []string{}))
						Expect(err).NotTo(HaveOccurred())
					})
				})

				Context("when DOCKER_AUTH_JWT_LOWERCASE_LABELS is enabled", func() {
					BeforeEach(func() {
						os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
						os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
						os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "true")
						os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
						os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
						os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
						os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())

						plugin := NewJWTAuthenticator(http.DefaultClient)
						authn = &plugin

						jwttoken, err := jwt.NewBuilder().
							Issuer("test-issuer").
							Audience([]string{"example.com"}).
							Subject("test-user").
							IssuedAt(time.Now()).
							Expiration(time.Now().Add(5*time.Minute)).
							Claim("test-claim-1", "test-value-1").
							Claim("test-claim-2", "TEST-VALUE-2").
							Claim("test-claim-3", "").
							Build()
						Expect(err).NotTo(HaveOccurred())

						headers := jws.NewHeaders()
						headers.Set(jws.KeyIDKey, keyID1)

						token, err = jwt.Sign(jwttoken, jwt.WithKey(jwa.RS256, signingKey1, jws.WithProtectedHeaders(headers)))
						Expect(err).NotTo(HaveOccurred())
					})

					AfterEach(func() {
						Expect(server.ReceivedRequests()).To(HaveLen(1))
					})

					It("returns true and labels", func() {
						actualResult, actualLabels, err := authn.Authenticate("oauth2accesstoken", api.PasswordString(token))
						Expect(actualResult).To(BeTrue())
						Expect(actualLabels).To(HaveKeyWithValue("iss", []string{"test-issuer"}))
						Expect(actualLabels).To(HaveKeyWithValue("sub", []string{"test-user"}))
						Expect(actualLabels).To(HaveKeyWithValue("aud", []string{"example.com"}))
						Expect(actualLabels).To(HaveKeyWithValue("test-claim-1", []string{"test-value-1"}))
						Expect(actualLabels).To(HaveKeyWithValue("test-claim-2", []string{"test-value-2"}))
						Expect(actualLabels).To(HaveKeyWithValue("test-claim-3", []string{}))
						Expect(err).NotTo(HaveOccurred())
					})
				})
			})
		})
	})

	Context("Stop()", func() {
		BeforeEach(func() {
			os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
			os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
			os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "false")
			os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
			os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
			os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
			os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())

			plugin := NewJWTAuthenticator(http.DefaultClient)
			authn = &plugin
		})

		It("does nothing", func() {
			authn.Stop()
		})
	})

	Context("Name()", func() {
		BeforeEach(func() {
			os.Setenv("DOCKER_AUTH_JWT_REQUIRED_AUD_CLAIM", "example.com")
			os.Setenv("DOCKER_AUTH_JWT_USERNAME", "oauth2accesstoken")
			os.Setenv("DOCKER_AUTH_JWT_LOWERCASE_LABELS", "false")
			os.Setenv("DOCKER_AUTH_JWT_JWKS_0_ENDPOINT", endpoint1)
			os.Setenv("DOCKER_AUTH_JWT_JWKS_1_ENDPOINT", endpoint2)
			os.Setenv("DOCKER_AUTH_JWT_JWKS_0_CA_PATH", caFile.Name())
			os.Setenv("DOCKER_AUTH_JWT_JWKS_1_CA_PATH", caFile.Name())

			plugin := NewJWTAuthenticator(http.DefaultClient)
			authn = &plugin
		})

		It("returns plugin name", func() {
			actual := authn.Name()
			Expect(actual).To(Equal("JWT"))
		})
	})
})
