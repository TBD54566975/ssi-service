package config

import (
	"strings"
	"sync"

	"github.com/tbd54566975/ssi-service/pkg/service/framework"
)

const (
	ServiceName    = "ssi-service"
	ServiceVersion = "0.0.3"
	APIVersion     = "v1"
)

var (
	si   *serviceInfo
	once sync.Once
)

// getServiceInfo provides serviceInfo as a singleton
func getServiceInfo() *serviceInfo {
	once.Do(func() {
		si = &serviceInfo{
			name: ServiceName,
			description: "The Self Sovereign Identity Service is a RESTful web service that facilitates all things relating" +
				" to DIDs, VCs, and related standards-based interactions.",
			version:      ServiceVersion,
			apiVersion:   APIVersion,
			servicePaths: make(map[framework.Type]string),
		}
	})

	return si
}

// serviceInfo is intended to be a (mostly) read-only singleton object for static service info
type serviceInfo struct {
	name         string
	description  string
	version      string
	apiBase      string
	apiVersion   string
	servicePaths map[framework.Type]string
}

func Name() string {
	return getServiceInfo().name
}

func Description() string {
	return getServiceInfo().description
}

func (si *serviceInfo) Version() string {
	return getServiceInfo().version
}

func SetAPIBase(url string) {
	if strings.LastIndexAny(url, "/") == len(url)-1 {
		url = url[:len(url)-1]
	}
	getServiceInfo().apiBase = url
}

func GetAPIBase() string {
	return getServiceInfo().apiBase
}

func SetServicePath(service framework.Type, path string) {
	// normalize path
	if strings.IndexAny(path, "/") == 0 {
		path = path[1:]
	}
	base := getServiceInfo().apiBase
	getServiceInfo().servicePaths[service] = strings.Join([]string{base, APIVersion, path}, "/")
}

func GetServicePath(service framework.Type) string {
	return getServiceInfo().servicePaths[service]
}
