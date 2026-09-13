# Compatibility Contract

Network Plugin Manager is branded, packaged, and deployed as a PastureStack component. A small set of inherited literals must remain while the 1.6 control-plane protocol is supported.

## Retained protocol and data identifiers

- Metadata API date: `/2016-07-29`
- Link-local metadata address used by the infrastructure catalog: `169.254.169.250`
- Docker control-plane labels under `io.rancher.*`
- Legacy CA fallback: `/var/lib/rancher/etc/ssl/ca.crt`
- Metadata fields and event semantics inherited from the Rancher 1.6 wire contract; their small adapters are maintained under `internal/`
- Legacy CNI driver value `rancher-bridge`, recognized alongside the PastureStack-native `pasture-bridge`
- Existing CNI runtime argument `RancherContainerUUID`, emitted together with the PastureStack-native `PlatformContainerUUID`

These strings are compatibility identifiers, not product names, image names, public service names, or claims of affiliation. Removing or renaming one without a coordinated Server, Agent, Catalog, metadata, and upgrade test can silently break host networking.

## PastureStack-native interfaces

- Executable: `network-plugin-manager`
- Image: `ghcr.io/pasturestack/network-plugin-manager`
- Service-discovery name: `metadata`
- Primary CA location: `/var/lib/pasturestack/etc/ssl/ca.crt`
- Source repository: `https://github.com/PastureStack/network-plugin-manager`

The compatibility CA path is read only when the PastureStack-native path is absent. Catalog templates must use PastureStack image names and reviewed numeric tags, with release digests checked separately, even while retained labels are required by the control-plane wire contract.

## Firewall backend migration

The `iptables-legacy` frontend remains an explicit compatibility mode
for hosts that intentionally use it with Docker's iptables firewall backend.
Hosts using `iptables-nft` use its separate compatibility CLI; Docker's native
`nftables` driver uses an owned nft table and Docker's documented bridge
firewall-mark integration. Ubuntu version does not select a mode: even on
Ubuntu 26.04 or later, use Docker's actual firewall driver and, for its
iptables driver, the active iptables frontend. An explicit mismatch fails at
startup. These are distinct modes, not interchangeable spellings for the same
rules. Native startup inspects old `iptables-nft`
rules and any already loaded legacy filter/NAT tables for active platform or
Docker hooks and FORWARD DROP policy. It does not load legacy modules just to
inspect an unused frontend. Docker's iptables modes also reject active
platform hooks in the opposite frontend; an unhooked chain declaration alone
does not count as live packet processing. Operators
migrating a legacy host must audit and remove its pre-existing legacy rules
under their own change control before enabling Docker native nftables; this
component never auto-imports or silently deletes such rules. The retained
metadata network schema and host-port rules are IPv4-only.

The host NAT and host-port `CATTLE_*` chains are owned exclusively by this
manager. Its general masquerade rules exclude the managed overlay subnet on
native nftables, iptables-nft, and iptables-legacy. The IPsec host-XFRM router
owns routes and XFRM state, not these chains. Upgrade this manager first,
confirm its reconciliation and source-preserving egress, then upgrade the
router; do not rely on a second plugin to patch a manager-owned chain.

For the optional per-host-subnet driver, the manager reads only active hosts'
canonical, non-overlapping subnet labels in the same Metadata environment.
It excludes those peer destinations from its own masquerade chain and allows
only peer-subnet-to-local-subnet forwarding (or the equivalent native nft mark
that Docker's bridge filter recognizes). Inactive registrations are ignored;
an active host lacking a valid label blocks reconciliation instead of opening
a broad rule. This is an unencrypted routed network; operators must trust and
protect the host transport. The CNI driver owns subnet assignment, while this
manager exclusively owns the firewall exception in each selected backend.

For the v0.8.13 upgrade case where Docker uses `iptables-nft` but a previous
manager left `CATTLE_*` hooks in a loaded legacy NAT table, use the dedicated
`iptables-legacy` frontend for inspection; the generic `iptables` alternative
may point to nft and cannot prove what is in the legacy table. Stop the old
dual-writing manager before changing rules. Save the affected legacy NAT and
filter tables, then verify that any proposed removal targets only exact
platform-owned `CATTLE_*` hooks and chains, with no Docker or third-party
references. Remove only those verified hooks and chains, read back both
backends, and check workload egress, DNS, and host ports before returning the
host to service. If ownership or references are unclear, stop and investigate.
Never flush a whole table, change a global policy, remove Docker rules, load
legacy modules as a workaround, or silently fall back to another backend.

Host-port authorization is scoped to the manager's own published DNAT targets
on every forwarded packet. The NAT hook sees only the first packet of a
conntracked UDP flow; relying on its firewall mark alone can drop later VXLAN
datagrams at Docker's bridge filter. The filter-path rule also requires DNAT
state and the exact target address, protocol, and port. It does not create a
host-wide accept rule or change Docker's default FORWARD policy.

Each managed bridge subnet may initiate forwarding, while traffic returning
to it is accepted only in `ESTABLISHED` or `RELATED` conntrack states.
Unsolicited traffic whose destination is a managed subnet is not admitted by
this rule. Native nftables applies Docker's configured bridge-accept mark on
both directions; the two iptables frontends use only the selected
`CATTLE_FORWARD` chain. This bounded rule is what permits current Docker
filters to carry Metadata, DNS, and normal workload egress.

For a CNI bridge marked `skipBridgeConfigureIP`, the workload uses an
external Layer 2 gateway. The manager therefore masquerades only its own DNAT
flows to an exact published address, protocol, and port, preventing replies
from bypassing the publishing host. Other bridge networks preserve source
addresses; only locally originated host-port traffic is masqueraded. When a
host port accepts loopback traffic, `route_localnet` is enabled only on that
specific managed bridge and is rechecked during reconciliation. No global
`route_localnet`, forwarding policy, or third-party NAT rule is changed.
