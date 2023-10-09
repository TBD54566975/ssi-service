# Authentication

Out of the box if you set the `AUTH_TOKEN` to a sha256 token value, then all API calls will require a bearer token that hashes to that. If `AUTH_TOKEN` is not set then no authentication is required.

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

The server uses the [Gin framework](https://github.com/gin-gonic/gin), which allows various kinds of middleware. Look in [`pkg/server/middleware/authn.go`](../../pkg/server/middleware/authn.go) and [`pkg/server/server.go`](../../pkg/server/server.go) for details on how you can wire up authentication and authorization for your use case. One such option is the https://github.com/zalando/gin-oauth2 framework.

## How to add Authentication to the SSI Service
1. Open [`pkg/server/middleware/authn.go`](../../pkg/server/middleware/authn.go) for a reference to where to add the proper code
```go
func setUpEngine(cfg config.ServerConfig, shutdown chan os.Signal) *gin.Engine {
	gin.ForceConsoleColor()
	middlewares := gin.HandlersChain{
		gin.Recovery(),
		gin.Logger(),
		middleware.Errors(shutdown),
		middleware.AuthMiddleware(),
	}
}
```

2. Open [`pkg/server/server.go`](../../pkg/server/server.go) and uncomment line 126
```go
// uncomment the below line to enable middle ware auth, see doc/config/auth.md for details
middleware.AuthMiddleware()
```

3. Reference the [Authentication](#authentication) section for how to create an `AUTH_TOKEN`

4. Update `.env` with the hash produced in step 3
```conf
AUTH_TOKEN="8e455e42e94a0f3ac17fe27e9c6a8475800d02c123ba9d2dc0cf1063ef52bd90"
```

5. Build and run the server. When making API calls, pass the preimage (unhashed data) in the header
```bash
export TOKEN=hunter2
curl -H "Authorization: Bearer $TOKEN"
```