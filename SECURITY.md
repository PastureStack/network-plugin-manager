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
- Use Go 1.27.0, verify `go.sum`, and build from the committed vendor tree without network fallback.
- Resolve exact direct Alpine runtime package versions from the pinned 3.23 branch and retain the resolved package manifest.
- Keep the runtime base image digest-pinned.
- Do not install Docker CLI in the runtime image; use only the bounded Docker socket operations implemented by this service.
- Run unit/race tests, vet, formatting, govulncheck, secret scanning, and Trivy/CycloneDX checks for source, binary, and the single runtime image before publishing.
- Reject every reported source, binary, or runtime vulnerability and secret; do not hide findings behind a repository-wide VEX exception.
- Publish a new immutable version when source or dependencies change; do not replace an existing release digest.

Report vulnerabilities privately to the PastureStack organization maintainers. Do not include credentials, internal addresses, customer data, or exploit details in public issues.
