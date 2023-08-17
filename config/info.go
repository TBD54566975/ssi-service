package config

import (
	"strings"

	"github.com/tbd54566975/ssi-service/pkg/service/framework"
)

const (
	ServiceName    = "ssi-service"
	ServiceVersion = "0.0.3"
	APIVersion     = "v1"
)

var (
	si = &serviceInfo{
		name: ServiceName,
		description: "The Self Sovereign Identity Service is a RESTful web service that facilitates all things relating" +
			" to DIDs, VCs, and related standards-based interactions.",
		version:      ServiceVersion,
		apiVersion:   APIVersion,
		servicePaths: make(map[framework.Type]string),
	}
)

// serviceInfo is intended to be a singleton object for static service info.
// WARNING: it is **NOT** currently thread safe.
type serviceInfo struct {
	name          string
	description   string
	version       string
	apiBase       string
	statusBaseUrl string
	apiVersion    string
	servicePaths  map[framework.Type]string
}

func Name() string {
	return si.name
}

func Description() string {
	return si.description
}

func (si *serviceInfo) Version() string {
	return si.version
}

func SetAPIBase(url string) {
	if strings.LastIndexAny(url, "/") == len(url)-1 {
		url = url[:len(url)-1]
	}
	si.apiBase = url
}

func GetAPIBase() string {
	return si.apiBase
}

func SetStatusBase(url string) {
	if strings.LastIndexAny(url, "/") == len(url)-1 {
		url = url[:len(url)-1]
	}
	si.statusBaseUrl = url
}

func GetStatusBase() string {
	return si.statusBaseUrl
}

func SetServicePath(service framework.Type, path string) {
	// normalize path
	if strings.IndexAny(path, "/") == 0 {
		path = path[1:]
	}
	si.servicePaths[service] = strings.Join([]string{si.apiBase, APIVersion, path}, "/")
}

func GetServicePath(service framework.Type) string {
	return si.servicePaths[service]
}
