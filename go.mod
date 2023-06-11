module github.com/chitoku-k/docker_auth-jwt-plugin

go 1.20

replace github.com/cesanta/docker_auth/auth_server => ./docker_auth/auth_server

require (
	github.com/cesanta/docker_auth/auth_server v0.0.0-20230301204333-39d6404f878d
	github.com/cesanta/glog v0.0.0-20150527111657-22eb27a0ae19
	github.com/lestrrat-go/jwx/v2 v2.0.8
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.1.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/lestrrat-go/blackmagic v1.0.1 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.4 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	golang.org/x/crypto v0.0.0-20220926161630-eccd6366d1be // indirect
)
