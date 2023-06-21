package middleware

import (
	"github.com/gin-gonic/gin"
)

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
			//c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			//c.Abort()
			//return
			c.Next()
		}
	}
}
