# Compatibility Contract

Network Plugin Manager is branded, packaged, and deployed as a PastureStack component. A small set of inherited literals must remain while the 1.6 control-plane protocol is supported.

## Retained protocol and data identifiers

- Metadata API date: `/2016-07-29`
- Link-local metadata address used by the infrastructure catalog: `169.254.169.250`
- Docker control-plane labels under `io.rancher.*`
- Legacy CA fallback: `/var/lib/rancher/etc/ssl/ca.crt`
- Vendored dependency import paths under `github.com/rancher/*`
- Existing CNI driver value `rancher-bridge`

These strings are compatibility identifiers, not product names, image names, public service names, or claims of affiliation. Removing or renaming one without a coordinated Server, Agent, Catalog, metadata, and upgrade test can silently break host networking.

## PastureStack-native interfaces

- Executable: `network-plugin-manager`
- Image: `ghcr.io/pasturestack/network-plugin-manager`
- Service-discovery name: `metadata`
- Primary CA location: `/var/lib/pasturestack/etc/ssl/ca.crt`
- Source repository: `https://github.com/PastureStack/network-plugin-manager`

The compatibility CA path is read only when the PastureStack-native path is absent. Catalog templates must use PastureStack image names and immutable digests even while retained labels are required by the control-plane wire contract.
