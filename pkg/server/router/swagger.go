package router

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Swagger wraps the gin swagger handler in our framework handler for usage in a router.
func Swagger(c *gin.Context) {
	ginSwagger.WrapHandler(swaggerFiles.Handler)(c)
}
