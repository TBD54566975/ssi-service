# SSI Service Helm Chart

This chart deploys an SSI Service environment on a Kubernetes cluster using the Helm package manager. SSI (Self-Sovereign Identity) Service is a web service that exposes the ssi-sdk as an HTTP API, supporting operations for Verifiable Credentials, Decentralized Identifiers, and more.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+

## Installing the Chart

To install the chart with the release name `my-release`:

```bash
git clone https://github.com/TBD54566975/ssi-service.git
cd ssi-service/charts
helm install my-ssi .
```

This command deploys SSI Service on the Kubernetes cluster with the default configuration.

## Configuration

The following table lists some of the configurable parameters of the SSI Service chart. See values.yaml for the full list.

| Field | Description |
|---|---|
| `fullnameOverride` | A string that overrides the full name of the resources. |
| `ssiService` | Configuration for the ssiService. |
| `ssiService.replicaCount` | The number of replicas for the ssiService. |
| `ssiService.image` | The image to use for the ssiService, including the `repository`, the `tag`, and the `pullPolicy`. |
| `ssiService.service` | The service details, including `type`, `port`, and `targetPort`. |
| `ssiService.resources` | The resources to allocate for the ssiService, including CPU and memory `requests`. |
| `ssiService.env` | The environment variables for the ssiService, such as `jaegerHttpUrl`. |
| `ssiService.ingress` | The ingress configuration, including `enabled` flag, `annotations`, `hosts`, `paths`, `tls`, and `secretName`. |
| `ssiService.istio` | The Istio configuration, including `virtualService` and `authorizationPolicy` options. |
| `ssiService.config` | The configuration content for running the service in a production environment. It includes configurations for the server, logging, CORS, services, and more. |
| `uniResolver` | Configuration for the universal resolver service. |
| `uniResolver.replicaCount` | The number of replicas for the uniResolver. |
| `uniResolver.image` | The image to use for the uniResolver, including the `repository`, the `tag`, and the `pullPolicy`. |
| `uniResolver.service` | The service details, including `type`, `port`, and `targetPort`. |
| `uniResolver.resources` | The resources to allocate for the uniResolver, including CPU and memory `requests`. |
| `uniResolver.port` | The port on which the uniResolver will be exposed. |
| `driverDidIon` | Configuration for the ION DID driver service. |
| `driverDidIon.replicaCount` | The number of replicas for the driverDidIon. |
| `driverDidIon.image` | The image to use for the driverDidIon, including the `repository`, the `tag`, and the `pullPolicy`. |
| `driverDidIon.service` | The service details, including `type`, `port`, and `targetPort`. |
| `driverDidIon.resources` | The resources to allocate for the driverDidIon, including CPU and memory `requests`. |
| `jaeger` | Configuration for the Jaeger service. |
| `jaeger.replicaCount` | The number of replicas for the Jaeger service. |
| `jaeger.image` | The image to use for the Jaeger service, including the `repository`, the `tag`, and the `pullPolicy`. |
| `jaeger.service` | The service details, including `type`, `port`, and `targetPort`. |
| `jaeger.resources` | The resources to allocate for the Jaeger service, including CPU and memory `requests`. |
| `tolerations`, `affinity`, `topologySpreadConstraints`, `nodeSelector` | (Commented out) Controls how pods are scheduled. Uncommenting and setting them can affect where and how pods are deployed in the cluster. |
| `redis-ha` | Configuration for the redis-ha installation. Not installed by default |

Note: For more information about the service's configuration options, refer to the `config` field in the `values.yaml` file.

## Dependencies

This chart has a dependency on the Redis HA chart, which is used for high-availability data persistence. If Redis HA is not yet installed or if it's disabled, it will be installed during the deployment of this chart if `redis-ha.enabled` is set to `true`. By default, `redis-ha.enabled` is set to `false`.

---

For more information, please read [the official Helm chart documentation](https://helm.sh/docs/topics/charts/).

---

Please note that the configuration, parameters, and default values can be modified as per your requirements.
