package middleware

import (
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
	}

*/

func AuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole := "userRole" // Retrieve user role from the JWT or context
		path := c.FullPath()

		switch {

		case userRole == "admin":
			// Admin has access to every endpoint
			c.Next()

		case userRole == "user" && path != "/admin-endpoint":
			// Users do not have access to the admin endpoint
			c.Next()

		default:
			// Normally you would return a 403 here, but for the sake of the example we will just call next
			// c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			// c.Abort()
			// return
			c.Next()
		}
	}
}
