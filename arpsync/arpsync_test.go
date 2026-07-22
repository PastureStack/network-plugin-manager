package arpsync

import (
	"testing"
	"time"

	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// Some of the tests can run only when in development,
// remember to disable this before commiting the code.
const inDevelopment = false

func TestDoSync(t *testing.T) {
	if !inDevelopment {
		t.Skip("not in development mode")
	}
	logrus.SetLevel(logrus.DebugLevel)
	logrus.Debugf("TestDoSync")
	mc, err := metadata.NewClientAndWait("http://169.254.169.250/2016-07-29")
	if err != nil {
		logrus.Errorf("error creating metadata client")
		t.Fail()
	}

	atw := &ARPTableWatcher{
		syncInterval: time.Duration(10) * time.Second,
		mc:           mc,
	}

	if err := atw.doSync(); err != nil {
		logrus.Errorf("arpsync: error doing a sync of the ARP table: %v", err)
	}
}

func TestARPEntryState(t *testing.T) {
	if got := arpEntryState("host"); got != netlink.NUD_REACHABLE {
		t.Fatalf("host ARP state = %d, want NUD_REACHABLE(%d)", got, netlink.NUD_REACHABLE)
	}

	if got := arpEntryState("container-id"); got != netlink.NUD_PERMANENT {
		t.Fatalf("container ARP state = %d, want NUD_PERMANENT(%d)", got, netlink.NUD_PERMANENT)
	}
}

func TestIsNetworkDriverContext(t *testing.T) {
	containers := map[string]*metadata.Container{
		"10.42.1.2": {ExternalId: "router", PrimaryMacAddress: "02:94:0f:aa:bb:cc"},
		"10.42.1.3": {ExternalId: "workload", PrimaryMacAddress: "02:94:0f:dd:ee:ff"},
	}

	if !isNetworkDriverContext("router", "02:94:0f:aa:bb:cc", containers) {
		t.Fatal("router container should be detected as network driver context")
	}

	if isNetworkDriverContext("workload", "02:94:0f:aa:bb:cc", containers) {
		t.Fatal("workload container must not be treated as network driver context")
	}
}

func TestExpectedARPEntrySkipsRemoteContainerInNetworkDriverContext(t *testing.T) {
	host := metadata.Host{UUID: "local-host"}
	remote := &metadata.Container{HostUUID: "remote-host", PrimaryMacAddress: "02:94:0f:11:22:33"}

	if _, manage := expectedARPEntry("router", "02:94:0f:aa:bb:cc", remote, host, true); manage {
		t.Fatal("router context should not pin remote container IPs to its own MAC")
	}
}
