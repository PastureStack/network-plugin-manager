package cniglue

import (
	"net"
	"testing"

	types100 "github.com/containernetworking/cni/pkg/types/100"
)

func TestPrimaryIPv4SelectsIPv4(t *testing.T) {
	result := &types100.Result{IPs: []*types100.IPConfig{
		{Address: net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}},
		{Address: net.IPNet{IP: net.ParseIP("10.42.0.7"), Mask: net.CIDRMask(24, 32)}},
	}}
	if got := PrimaryIPv4(result); got != "10.42.0.7" {
		t.Fatalf("PrimaryIPv4() = %q", got)
	}
}
