# Security

Network Plugin Manager is a privileged per-host system service. A compromise can alter host routes, firewall rules, CNI files, namespaces, or containers.

## Deployment requirements

- Pull only the digest pinned by the reviewed PastureStack catalog.
- Restrict deployment to the infrastructure environment and one instance per host.
- Mount only the Docker socket, required host network state, kernel modules, and CNI directories described by the catalog.
- Obtain metadata from the link-local host endpoint supplied by the control plane.
- Never place credentials in image arguments, labels, repository files, or command-line flags.
- Treat debug logs and host networking output as operationally sensitive.

## Build requirements

- Build from the public source commit named by `org.opencontainers.image.revision`.
- Verify the Go and Docker CLI archive hashes before extraction.
- Keep the runtime base image digest-pinned.
- Run unit tests, race tests, `go vet`, formatting checks, build-policy checks, secret scanning, an SBOM inventory, and High/Critical vulnerability scanning before publishing.
- Publish a new immutable version when source or dependencies change; do not replace an existing release digest.

Report vulnerabilities privately to the PastureStack organization maintainers. Do not include credentials, internal addresses, customer data, or exploit details in public issues.
