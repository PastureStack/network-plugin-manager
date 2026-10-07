# PastureStack Network Plugin Manager

Network Plugin Manager reconciles host routes, CNI configuration, ARP entries, connection tracking, host-port rules, and network-driver helpers from PastureStack metadata. It is a privileged system component deployed once per host by the PastureStack infrastructure catalog.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/plugin-manager`](https://github.com/rancher/plugin-manager). This GitHub fork retains the upstream Git history, authorship, dates, and license notices. PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

## Runtime image

The current release is `v0.8.22`. Release assets include source and image
SBOMs, SHA256 checksums, and build provenance. Obtain the immutable image
identity from the checksum-covered `published.txt` in the release. Catalog
integration and real-host lifecycle checks are separate from image publication.

Managed bridge subnets can initiate
outbound traffic and receive established or related replies. Shared overlay
subnets used by IPsec and VXLAN can also receive new connections from the
same validated subnet through the exact managed bridge. Existing templates
with `hostNat: true` retain this behavior; current templates declare
`allowSharedSubnetIngress: true` explicitly. Per-host subnets remain limited
to the active peer CIDRs derived from host labels. These rules keep Metadata,
DNS, and cross-host workload traffic reachable behind current Docker bridge
filters without changing the host's global policy.
Every forwarding exception is bound to the exact validated CNI bridge and
subnet pair; missing or conflicting bridge metadata fails before any firewall
change. This prevents traffic arriving on an unrelated host interface from
claiming a managed source prefix.
Host ports on a flat L2 network receive target-scoped DNAT masquerading so
replies return through the publishing host even when workloads use an
external gateway. Loopback host-port access enables `route_localnet` only on
the exact managed bridge that needs it, after a bridge-scoped raw-prerouting
drop for `127.0.0.0/8` is live. The original per-bridge value is recorded on
the host-mounted runtime state and restored before the final guard is removed.
Overlay host ports retain client source addresses except for locally
originated access. Obtain the immutable
image identity from the release's checksum-covered
[`published.txt`](https://github.com/PastureStack/network-plugin-manager/releases/latest/download/published.txt)
rather than copying an older release digest.

The manager also closes two control-plane convergence gaps without moving
responsibility between plugins. If Metadata temporarily omits the primary IP
of a running container that publishes a host port, the manager reads that
exact container's network namespace and accepts an address only when exactly
one IPv4 address belongs to the already validated managed bridge subnet. It
inspects the Docker PID before and after the namespace read; a stopped or
replaced process, an absent subnet, or zero/multiple matching addresses fails
closed and leaves the previously working rule set in place for retry.

When more than one local network driver provides the same CNI executable, the
manager deterministically selects the highest numeric OCI image version, with
the immutable container ID as a stable tie-breaker. The host-side wrapper is
bound to that exact inspected container ID and executes the selected driver's
private `/opt/cni/bin` bundle with a private `CNI_PATH`; it does not list and
reselect a same-labelled container at invocation time. Binary names are
strictly validated, wrappers are installed atomically as regular mode-0700
files, and content, type, or permission drift is repaired. Older drivers that
do not yet contain a private bundle retain the existing shared-binary fallback.
The driver still owns its CNI data plane; Network Plugin Manager owns host
NAT, forwarding, host-port reconciliation, and materializing the CNI
configuration supplied by Metadata.

CNI configuration upgrades also reconcile the known historical IPsec file.
When current Metadata requests `10-pasturestack.conf` with the native bridge
and metadata IPAM contract, the manager validates and atomically writes all
desired configs before retiring an unrequested `10-rancher.conf` whose
network name, bridge type, and IPAM type exactly match the legacy platform
contract. Its unchanged contents remain in
`10-rancher.conf.pasturestack-retired`, outside the active `.conf`/`.json`
set. Rolling back to the exact legacy Metadata contract retires the known
native counterpart in the same way, so both configs cannot run together.
Legacy Metadata remains supported; unrelated administrator files remain
untouched. Malformed or ambiguous old files, symlinks, and conflicting backup
contents fail reconciliation explicitly. This is a bounded config migration,
not a claim that every host or firewall upgrade is safe.

The current preflight inspects already loaded legacy tables using an
independent iptables-legacy executable. Active old platform or Docker hooks
in the other frontend block startup; an unhooked chain declaration alone does
not select or block a backend. The manager never migrates host rules or
switches Docker's selected backend automatically.

A bounded two-host Ubuntu 26.04 / Docker 29 gate exercised the release
candidate through a managed-service upgrade. Docker native nftables on one
host and `iptables-nft` on the other passed IPsec, VXLAN, per-host-subnet, and
flat Layer 2 cross-host traffic, Metadata, DNS, platform egress, and host-port
checks. The second host passed the same checks after a Docker restart and
after an explicit switch to `iptables-legacy`, then was restored to its
original `iptables-nft` frontend. Injected CNI-wrapper drift was restored to
the same exact selected provider on both hosts. This component does not
migrate or remove old rules automatically. Verify the official image digest
and perform controlled host migration for each deployment; Catalog and Server
integration are separate release gates.

The maintained image coordinate is:

```text
ghcr.io/pasturestack/network-plugin-manager:<version>
```

Production catalog templates reference a reviewed pure numeric version tag; the published manifest digest is verified and recorded separately as release evidence. This image is not a standalone application: it requires host networking, host PID visibility, the Docker socket, host network state, CNI directories, and metadata generated by the PastureStack control plane.

The primary executable is `network-plugin-manager`. Its default metadata endpoint is `http://metadata/2016-07-29`; the catalog supplies the link-local endpoint used by each host deployment.

Since `v0.8.16`, the official per-host-subnet template's explicit
`__host_label__:` subnet reference is resolved against the local host's Metadata
labels before calculating host NAT and forwarding rules. Missing required labels
fail closed, preserving existing applied hooks. Literal network subnets remain
unchanged. This component does not resolve CNI stdin; the IPsec/VXLAN image
owns that entrypoint, and neither component changes Docker's firewall backend.

## Host firewall backends

The new `--firewall-backend` setting separates `auto`, `iptables-nft`,
`iptables-legacy`, and Docker's native `nftables`. `auto` follows the Docker
daemon's reported firewall backend and, for Docker's iptables backend, the
active iptables frontend. Ubuntu 26.04 and later can also intentionally run
Docker with `iptables-legacy` or `iptables-nft`; the OS release alone never
selects `nftables` or triggers a backend migration. The manager **never**
selects legacy merely because its executable exists, falls back to legacy
after a failure, or enables legacy kernel modules. An explicit mode that
disagrees with Docker fails at startup.

For Docker 29's native nftables backend, configure the Docker daemon with
`"firewall-backend": "nftables"` and
`"bridge-accept-fwmark": "0x1068/0x1068"`. Enable and persist host
`net.ipv4.ip_forward=1` **before restarting Docker**; otherwise a fresh
Ubuntu 26.04 installation may fail to start Docker after reboot. The manager
checks Docker's installed mark rule and rejects stale platform xtables hooks,
active Docker xtables NAT hooks, or an old xtables FORWARD DROP policy in the
loaded frontends. It reports these conditions for
an operator to migrate explicitly; it does not change a global FORWARD policy
or rewrite Docker's own nftables tables. Hosts using `iptables-legacy` keep
their explicitly selected compatibility path regardless of Ubuntu version.
Do not switch a production host between backends without a backup and a
maintenance-window verification of container egress, DNS, host ports, Docker
restart, and host reboot.

On an `iptables-nft` host, a loaded legacy NAT table is inspected with the
dedicated `iptables-legacy` executable. An old `CATTLE_*` hook there does not
make legacy Docker's active backend, but an active hook in the opposite
frontend still blocks manager startup; so does an active legacy Docker NAT
hook or an uninspectable loaded table. The manager writes only to Docker's
selected backend and never silently removes old hooks. See the bounded cleanup steps
in [COMPATIBILITY.md](COMPATIBILITY.md).

Host NAT in all three backends excludes destinations within each network's
configured `bridgeSubnet` from its general masquerade rules, preserving the
source address for same-subnet overlay traffic. This component alone owns its
host NAT and host-port chains; the IPsec router must not insert bypasses or
forwarding rules into them. IKE SNAT and container-namespace compatibility
rules are separate. Upgrade this manager and verify it is healthy before
upgrading the IPsec router that no longer writes a compensating host bypass.
Cross-host behavior still requires deployment-level validation.

The image healthcheck waits until both the host NAT and host-port watchers
have successfully reconciled current metadata. A transient metadata delay
retries without claiming readiness; a later failed rule update revokes it.

This implementation handles the existing IPv4 PastureStack overlay/host-port
contract; it does not add IPv6 workload networking. Docker's native nftables
firewall backend remains experimental upstream, so deploy it only on a
tested Docker version and host configuration.

## Build and test

The maintained source uses Go Modules with Go 1.27.0, Moby API 1.55.0/client 0.5.1, CNI 1.3.0, and CNI plugins 1.9.1. The old 2016 Docker Engine API, fsouza event client, Rancher cniglue/event-subscriber helpers, and GOPATH dependency path are no longer compiled. The runtime talks to the mounted Docker socket through the bounded Moby client and two small `curl`/`jq` compatibility calls; it no longer bundles a second Docker CLI.

The Alpine 3.23 base image is digest-pinned. Direct runtime packages are exact-version locked in `alpine-apk.lock`, and the complete resolved APK manifest is retained in the image as build evidence. The runtime no longer inherits Ubuntu's unrelated `rust-coreutils` and system package vulnerability surface. The image exporter normalizes file timestamps to the source commit time.

```bash
make test
make validate
bash scripts/check-build-downloads
VERSION_OVERRIDE=v0.8.22 IMAGE_NAMESPACE=local/pasturestack make package
```

Pull requests and `main` run one non-publishing gate: tests, vet/format checks, govulncheck, a reproducible binary build, one runtime image build, and Trivy scans plus CycloneDX SBOMs for the source, binary, and image. All reported vulnerabilities and secrets fail the gate. Publishing remains a separate, explicitly authorized operation.

The opt-in, root-only host NAT and host-port VM tests reuse the runtime's
read-only Docker firewall detection before changing any rules. This also
recognizes older Docker APIs without `FirewallBackend.Driver` and avoids
probing unloaded legacy tables on nft-only hosts. Run them only on a
disposable VM with a rollback point; ordinary CI does not execute them.

## Compatibility and security

Some legacy API paths, Docker labels, filesystem paths, and dependency namespaces are protocol or data contracts. They are isolated and documented in [COMPATIBILITY.md](COMPATIBILITY.md), rather than exposed as PastureStack branding.

This component is intentionally privileged. Review [SECURITY.md](SECURITY.md) before changing mounts, capabilities, metadata trust, or Docker access.

## License and attribution

The inherited project remains licensed under [Apache License 2.0](LICENSE). PastureStack does not claim authorship of inherited work. See [ORIGIN.md](ORIGIN.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for provenance and bundled dependency notices.
