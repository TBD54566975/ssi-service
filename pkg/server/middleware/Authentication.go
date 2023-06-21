package middleware

import (
	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		// This is a dummy check here. You should do your actual JWT token verification.
		if token == "" {
			/*
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization is required"})
				c.Abort()
				return
			*/
		}
		// Assuming that the token is valid and we got the user info from the JWT token.
		// You should replace it with actual user info.
		user := "user"
		c.Set("user", user)
		c.Next()
	}
}
