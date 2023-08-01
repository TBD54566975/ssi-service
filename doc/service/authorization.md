# Authentication

Out of the box if you set the AUTH_TOKEN to a sha256 token value, then all api calls will require a bearer token that hashes to that. If AUTH_TOKEN is not set then no authentication is required.

Generate a token by hashing the super secure token of `hunter2`:
```sh
export AUTH_TOKEN=$(echo -n "hunter2" | shasum -a 256)
```

Then use `hunter2` as a Bearer token: 

```sh
export TOKEN=hunter2
curl -H "Authorization: Bearer $TOKEN" ....
```

# Extending Authentication and Authorization for production environments

The ssi server uses the Gin framework from Golang, which allows various kinds of middleware. Look in `pkg/middleware/Authentication.go` and `pkg/middleware/Authorization.go` for details on how you can wire up authentication and authorization for your use case. One such option is the https://github.com/zalando/gin-oauth2 framework.

