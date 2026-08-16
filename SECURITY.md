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
- Verify the Go, Docker CLI source, and Buildx source archive hashes before extraction.
- Build Docker CLI and Buildx with Go 1.26.6 from the commits referenced by verified upstream release tags.
- Verify the Docker CLI module sums and copy that exact Docker CLI binary into the runtime image.
- Apply the checksum-recorded Buildx patch and reject the build if the resulting binary still records the legacy Docker module.
- Resolve exact direct Ubuntu package versions only from the locked Canonical snapshot and retain the complete resolved package manifests.
- Keep the runtime base image digest-pinned.
- Run unit tests, race tests, `go vet`, formatting checks, build-policy checks, secret scanning, an SBOM inventory, and High/Critical vulnerability scanning before publishing.
- Reject all Critical or High source and runtime findings. The disposable builder may assess only unfixed `linux-libc-dev` findings when an exact-package OpenVEX document proves the kernel implementation is absent from both the header-only build input and the runtime image; that assessment expires on 2026-09-15 and all other builder findings fail the gate.
- Publish a new immutable version when source or dependencies change; do not replace an existing release digest.

Report vulnerabilities privately to the PastureStack organization maintainers. Do not include credentials, internal addresses, customer data, or exploit details in public issues.
