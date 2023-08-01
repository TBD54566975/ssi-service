package config

import (
	"strings"
	"sync"

	"github.com/tbd54566975/ssi-service/pkg/service/framework"
)

const (
	ServiceName    = "ssi-service"
	ServiceVersion = "0.0.3"
)

var (
	serviceInfo *ServiceInfo
	once        sync.Once
)

// GetServiceInfo provides ServiceInfo as a singleton
func GetServiceInfo() *ServiceInfo {
	once.Do(func() {
		serviceInfo = &ServiceInfo{
			name: ServiceName,
			description: "The Self Sovereign Identity Service is a RESTful web service that facilitates all things relating" +
				" to DIDs, VCs, and related standards-based interactions.",
			version:      ServiceVersion,
			apiVersion:   "v1",
			servicePaths: make(map[framework.Type]string),
		}
	})

	return serviceInfo
}

// ServiceInfo is intended to be a (mostly) read-only singleton object for static service info
type ServiceInfo struct {
	name         string
	description  string
	version      string
	apiBase      string
	apiVersion   string
	servicePaths map[framework.Type]string
}

func (si *ServiceInfo) Name() string {
	return si.name
}

func (si *ServiceInfo) Description() string {
	return si.description
}

func (si *ServiceInfo) Version() string {
	return si.version
}

func (si *ServiceInfo) SetAPIBase(url string) {
	if strings.LastIndexAny(url, "/") == len(url)-1 {
		url = url[:len(url)-1]
	}
	si.apiBase = url
}

func (si *ServiceInfo) GetAPIBase() string {
	return si.apiBase
}

func (si *ServiceInfo) SetServicePath(service framework.Type, path string) {
	if strings.IndexAny(path, "/") == 0 {
		path = path[1:]
	}
	si.servicePaths[service] = strings.Join([]string{si.apiBase, si.apiVersion, path}, "/")
}

func (si *ServiceInfo) GetServicePath(service framework.Type) string {
	return si.servicePaths[service]
}
