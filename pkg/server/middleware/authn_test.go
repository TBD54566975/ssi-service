package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestAuthMiddleware(t *testing.T) {
	// Set the AUTH_TOKEN environment variable for testing
	t.Setenv("AUTH_TOKEN", "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7") // sha256 hash of "hunter2"

	// Create a new gin engine
	r := gin.Default()

	// Add the AuthMiddleware to the gin engine
	r.Use(AuthMiddleware())

	// Add a test route
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Create a request with the correct Authorization header
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Add("Authorization", "Bearer hunter2")

	// Create a response recorder
	w := httptest.NewRecorder()

	// Serve the request
	r.ServeHTTP(w, req)

	// Assert that the status code is 200 OK
	assert.Equal(t, http.StatusOK, w.Code)

	// Create a request with an incorrect Authorization header
	req, _ = http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Add("Authorization", "Bearer nonsense")

	// Reset the response recorder
	w = httptest.NewRecorder()

	// Serve the request
	r.ServeHTTP(w, req)

	// Assert that the status code is 401 Unauthorized
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestNoAuthMiddleware(t *testing.T) {
	// no auth token so things just work
	t.Setenv("AUTH_TOKEN", "")

	// Create a new gin engine
	r := gin.Default()

	// Add the AuthMiddleware to the gin engine
	r.Use(AuthMiddleware())

	// Add a test route
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Create a request with the correct Authorization header
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)

	// Create a response recorder
	w := httptest.NewRecorder()

	// Serve the request
	r.ServeHTTP(w, req)

	// Assert that the status code is 200 OK
	assert.Equal(t, http.StatusOK, w.Code)
}
