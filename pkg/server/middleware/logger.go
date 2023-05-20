package middleware

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
)

// Logger logs request info before and after a handler runs.
// logs to stdout in the following format:
//
//	TraceID : (StatusCode) HTTPMethod Path -> IPAddr (latency)
//	e.g. 12345 : (200) GET /users/1 -> 192.168.1.0 (4ms)
func Logger(logger logrus.FieldLogger, notLogged ...string) gin.HandlerFunc {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	skip := make(map[string]struct{})
	if length := len(notLogged); length > 0 {
		for _, p := range notLogged {
			skip[p] = struct{}{}
		}
	}

	return func(c *gin.Context) {
		path := c.Request.URL.Path
		start := time.Now()
		clientIP := c.ClientIP()
		traceID := c.Value(framework.TraceIDKey.String())
		referer := c.Request.Referer()
		clientUserAgent := c.Request.UserAgent()
		r := c.Request

		beforeEntry := logger.WithFields(logrus.Fields{
			"hostname":  hostname,
			"clientIP":  clientIP,
			"method":    c.Request.Method,
			"path":      path,
			"referer":   referer,
			"userAgent": clientUserAgent,
			"remote":    r.RemoteAddr,
		})
		beforeEntry.Infof("%s : started", traceID)

		// run the request
		c.Next()

		stop := time.Since(start)
		latency := int(math.Ceil(float64(stop.Nanoseconds()) / 1000000.0))
		statusCode := c.Writer.Status()
		dataLength := c.Writer.Size()
		if dataLength < 0 {
			dataLength = 0
		}

		if _, ok := skip[path]; ok {
			return
		}

		afterEntry := logger.WithFields(logrus.Fields{
			"hostname":   hostname,
			"statusCode": statusCode,
			"latency":    latency,
			"clientIP":   clientIP,
			"method":     c.Request.Method,
			"path":       path,
			"referer":    referer,
			"dataLength": dataLength,
			"userAgent":  clientUserAgent,
			"remote":     r.RemoteAddr,
		})

		if len(c.Errors) > 0 {
			afterEntry.Error(c.Errors.ByType(gin.ErrorTypePrivate).String())
		} else {
			msg := fmt.Sprintf("%s : completed", traceID)
			switch {
			case statusCode >= http.StatusInternalServerError:
				afterEntry.Error(msg)
			case statusCode >= http.StatusBadRequest:
				afterEntry.Warn(msg)
			default:
				afterEntry.Info(msg)
			}
		}
	}
}
