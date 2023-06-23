package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

/*
To use this middleware, you need to add it to your gin router in server.go:

// setUpEngine creates the gin engine and sets up the middleware based on config
func setUpEngine(cfg config.ServerConfig, shutdown chan os.Signal) *gin.Engine {
	gin.ForceConsoleColor()
	middlewares := gin.HandlersChain{
		gin.Recovery(),
		gin.Logger(),
		middleware.Errors(shutdown),
		middleware.AuthMiddleware(),
		middleware.AuthorizationMiddleware(),
	}


*/

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		// This is a dummy check here. You should do your actual JWT token verification.
		if token == "IF YOU SET IT TO THIS VALUE IT WILL FAIL" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization is required"})
			c.Abort()
			return
		}
		// Assuming that the token is valid and we got the user info from the JWT token.
		// You should replace it with actual user info.
		user := "user"
		c.Set("user", user)
		c.Next()
	}
}
