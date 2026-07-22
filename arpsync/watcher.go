package arpsync

import (
	"net"
	"strconv"
	"time"

	"github.com/PastureStack/network-plugin-manager/identity"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/PastureStack/network-plugin-manager/network"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/docker/engine-api/client"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var (
	// DefaultSyncInterval specifies the default value for arpsync interval in seconds
	DefaultSyncInterval = 5
	syncLabel           = "io.rancher.network.arpsync"
)

// ARPTableWatcher checks the ARP table periodically for invalid entries
// and programs the appropriate ones if necessary based on info available
// from the platform metadata service
type ARPTableWatcher struct {
	syncInterval     time.Duration
	mc               metadata.Client
	dc               *client.Client
	knownRouters     map[string]metadata.Container
	routerApplyTries int
	lastApplied      time.Time
}

// Watch starts the go routine to periodically check the ARP table
// for any discrepancies
func Watch(syncIntervalStr string, mc metadata.Client, dc *client.Client) error {
	logrus.Debugf("arpsync: syncIntervalStr: %v", syncIntervalStr)

	syncInterval := DefaultSyncInterval
	if i, err := strconv.Atoi(syncIntervalStr); err == nil {
		syncInterval = i

	}

	atw := &ARPTableWatcher{
		syncInterval: time.Duration(syncInterval) * time.Second,
		mc:           mc,
		dc:           dc,
		knownRouters: map[string]metadata.Container{},
	}

	go mc.OnChange(120, atw.onChangeNoError)

	return nil
}

func (atw *ARPTableWatcher) onChangeNoError(version string) {
	logrus.Debugf("arpsync: metadata version: %v, lastApplied: %v", version, atw.lastApplied)
	timeSinceLastApplied := time.Now().Sub(atw.lastApplied)
	if timeSinceLastApplied < atw.syncInterval {
		timeToSleep := atw.syncInterval - timeSinceLastApplied
		logrus.Debugf("arpsync: sleeping for %v", timeToSleep)
		time.Sleep(timeToSleep)
	}
	if err := atw.doSync(); err != nil {
		logrus.Errorf("arpsync: while syncing, got error: %v", err)
	}
	atw.lastApplied = time.Now()
}

func buildContainersMap(containers []metadata.Container,
	network metadata.Network) (map[string]*metadata.Container, error) {
	containersMap := make(map[string]*metadata.Container)

	for index, aContainer := range containers {
		if !(aContainer.PrimaryIp != "" &&
			aContainer.PrimaryMacAddress != "" &&
			aContainer.NetworkUUID == network.UUID) {
			continue
		}
		containersMap[aContainer.PrimaryIp] = &containers[index]
	}

	return containersMap, nil
}

func (atw *ARPTableWatcher) doSync() error {
	host, err := identity.LocalHost(atw.mc, atw.dc)
	if err != nil {
		return errors.Wrap(err, "get local host")
	}

	containers, err := atw.mc.GetContainers()
	if err != nil {
		return errors.Wrap(err, "error fetching containers from metadata")
	}

	var lastError error
	localNetworks, routers, err := network.LocalNetworks(atw.mc, atw.dc)
	if err != nil {
		return errors.Wrap(err, "get local networks")
	}

	for _, localNetwork := range localNetworks {
		if routers[localNetwork.UUID].Labels[syncLabel] != "true" {
			continue
		}

		containersMap, err := buildContainersMap(containers, localNetwork)
		if err != nil {
			return errors.Wrap(err, "building containers map")
		}

		networkDriverMacAddress := routers[localNetwork.UUID].PrimaryMacAddress
		if networkDriverMacAddress == "" {
			continue
		}

		err = syncArpTable("host", networkDriverMacAddress, containersMap, host)
		if err != nil {
			lastError = err
		}

		if atw.knownRouters[localNetwork.UUID].PrimaryMacAddress != networkDriverMacAddress || atw.routerApplyTries < 10 {
			if atw.knownRouters[localNetwork.UUID].PrimaryMacAddress != networkDriverMacAddress {
				atw.routerApplyTries = 0
			}

			atw.routerApplyTries++
			logrus.Infof("Network router changed, syncing ARP tables %d/10 in containers, new MAC: %v", atw.routerApplyTries, networkDriverMacAddress)
		}

		err = network.ForEachContainerNS(atw.dc, atw.mc, localNetwork.UUID, func(container metadata.Container, _ ns.NetNS) error {
			return syncArpTable(container.ExternalId, networkDriverMacAddress, containersMap, host)
		})
		if err != nil {
			lastError = err
		}
	}

	if lastError == nil {
		atw.knownRouters = routers
	}

	return lastError
}

func syncArpTable(context string, networkDriverMacAddress string, containersMap map[string]*metadata.Container, host metadata.Host) error {
	// Read the ARP table
	entries, err := netlink.NeighList(0, netlink.FAMILY_V4)
	if err != nil {
		logrus.Errorf("arpsync: error fetching entries from ARP table")
		return err
	}
	logrus.Debugf("arpsync: entries=%+v", entries)

	var lastError error
	seen := map[string]bool{}
	localIPs := localInterfaceIPs()
	networkDriverContext := isNetworkDriverContext(context, networkDriverMacAddress, containersMap)

	for _, aEntry := range entries {
		if aEntry.IP == nil {
			continue
		}
		seen[aEntry.IP.String()] = true

		if container, found := containersMap[aEntry.IP.String()]; found {
			expected, manageEntry := expectedARPEntry(context, networkDriverMacAddress, container, host, networkDriverContext)
			if !manageEntry {
				if aEntry.HardwareAddr.String() == networkDriverMacAddress {
					logrus.Infof("arpsync: (%s) deleting router self-referential ARP entry found=%+v for remote container", context, aEntry)
					if err := deleteARPEntry(context, aEntry); err != nil {
						lastError = err
					}
				}
				continue
			}

			if aEntry.HardwareAddr.String() != expected {
				logrus.Infof("arpsync: (%s) wrong ARP entry found=%+v(expected: %v) for local container, fixing it", context, aEntry, expected)
				if err := fixARPEntry(context, aEntry, expected); err != nil {
					lastError = err
				}
			}
		} else {
			logrus.Debugf("arpsync: container not found for ARP entry: %+v", aEntry)
		}
	}

	for ip, container := range containersMap {
		if seen[ip] || localIPs[ip] {
			continue
		}

		expected, manageEntry := expectedARPEntry(context, networkDriverMacAddress, container, host, networkDriverContext)
		if !manageEntry {
			continue
		}

		if err := addARPEntry(context, ip, expected); err != nil {
			lastError = err
		}
	}

	return lastError
}

func isNetworkDriverContext(context string, networkDriverMacAddress string, containersMap map[string]*metadata.Container) bool {
	for _, container := range containersMap {
		if container.ExternalId == context && container.PrimaryMacAddress == networkDriverMacAddress {
			return true
		}
	}

	return false
}

func expectedARPEntry(context string, networkDriverMacAddress string, container *metadata.Container, host metadata.Host, networkDriverContext bool) (string, bool) {
	if container.HostUUID == host.UUID {
		return container.PrimaryMacAddress, true
	}

	if networkDriverContext {
		return "", false
	}

	return networkDriverMacAddress, true
}

func localInterfaceIPs() map[string]bool {
	localIPs := map[string]bool{}
	links, err := netlink.LinkList()
	if err != nil {
		logrus.Errorf("arpsync: error listing local links: %v", err)
		return localIPs
	}

	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			logrus.Errorf("arpsync: error listing addresses for link %s: %v", link.Attrs().Name, err)
			continue
		}
		for _, addr := range addrs {
			if addr.IP != nil {
				localIPs[addr.IP.String()] = true
			}
		}
	}

	return localIPs
}

func addARPEntry(context string, ipAddress string, macAddress string) error {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return errors.Errorf("invalid IP address %s", ipAddress)
	}

	hwAddr, err := net.ParseMAC(macAddress)
	if err != nil {
		logrus.Errorf("arpsync: couldn't parse MAC address(%v): %v", macAddress, err)
		return err
	}

	routes, err := netlink.RouteGet(ip)
	if err != nil {
		logrus.Errorf("arpsync: (%s) error resolving route for missing ARP entry %s: %v", context, ipAddress, err)
		return err
	}
	if len(routes) == 0 {
		return errors.Errorf("no route found for missing ARP entry %s", ipAddress)
	}

	newEntry := netlink.Neigh{
		LinkIndex:    routes[0].LinkIndex,
		IP:           ip,
		HardwareAddr: hwAddr,
		State:        arpEntryState(context),
	}

	logrus.Infof("arpsync: (%s) missing ARP entry for %s, adding MAC %s on link %d with state %d", context, ipAddress, macAddress, routes[0].LinkIndex, newEntry.State)
	if err := netlink.NeighSet(&newEntry); err != nil {
		logrus.Errorf("arpsync: error adding ARP entry: %v", err)
		return err
	}

	return nil
}

func deleteARPEntry(context string, entry netlink.Neigh) error {
	if err := netlink.NeighDel(&entry); err != nil {
		logrus.Errorf("arpsync: (%s) error deleting ARP entry: %v", context, err)
		return err
	}
	return nil
}

func arpEntryState(context string) int {
	if context == "host" {
		return netlink.NUD_REACHABLE
	}

	return netlink.NUD_PERMANENT
}

func fixARPEntry(context string, oldEntry netlink.Neigh, newMACAddress string) error {
	var err error
	var newHardwareAddr net.HardwareAddr
	if newHardwareAddr, err = net.ParseMAC(newMACAddress); err != nil {
		logrus.Errorf("arpsync: couldn't parse MAC address(%v): %v", newMACAddress, err)
		return err
	}
	newEntry := oldEntry
	newEntry.HardwareAddr = newHardwareAddr
	newEntry.State = arpEntryState(context)
	if err = netlink.NeighSet(&newEntry); err != nil {
		logrus.Errorf("arpsync: error changing ARP entry: %v", err)
		return err
	}
	return nil
}
