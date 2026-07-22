package events

import (
	"os"
	"path"

	"github.com/fsouza/go-dockerclient"
)

const (
	defaultUnixSocket = "unix:///var/run/docker.sock"
)

func NewDockerClient() (*docker.Client, error) {
	apiVersion := os.Getenv("DOCKER_API_VERSION")
	endpoint := defaultUnixSocket

	if os.Getenv("CATTLE_DOCKER_USE_BOOT2DOCKER") == "true" {
		endpoint = os.Getenv("DOCKER_HOST")
		certPath := os.Getenv("DOCKER_CERT_PATH")
		tlsVerify := os.Getenv("DOCKER_TLS_VERIFY") != ""

		if tlsVerify && certPath != "" {
			cert := path.Join(certPath, "cert.pem")
			key := path.Join(certPath, "key.pem")
			ca := path.Join(certPath, "ca.pem")
			if apiVersion == "" {
				return docker.NewTLSClient(endpoint, cert, key, ca)
			}
			return docker.NewVersionedTLSClient(endpoint, cert, key, ca, apiVersion)
		}
	}

	if apiVersion == "" {
		return docker.NewClient(endpoint)
	}
	return docker.NewVersionedClient(endpoint, apiVersion)
}
