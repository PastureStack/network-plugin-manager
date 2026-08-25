package main

import (
	"context"
	"fmt"
	"os"

	"github.com/PastureStack/network-plugin-manager/arpsync"
	"github.com/PastureStack/network-plugin-manager/binexec"
	"github.com/PastureStack/network-plugin-manager/cniconf"
	"github.com/PastureStack/network-plugin-manager/conntracksync"
	"github.com/PastureStack/network-plugin-manager/events"
	"github.com/PastureStack/network-plugin-manager/hostnat"
	"github.com/PastureStack/network-plugin-manager/hostports"
	"github.com/PastureStack/network-plugin-manager/internal/metadata"
	"github.com/PastureStack/network-plugin-manager/macsync"
	"github.com/PastureStack/network-plugin-manager/network"
	"github.com/PastureStack/network-plugin-manager/reaper"
	"github.com/PastureStack/network-plugin-manager/routesync"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// VERSION of the binary, that can be changed during build
var VERSION = "v0.0.0-dev"

func main() {
	app := &cli.Command{
		Name:    "network-plugin-manager",
		Version: VERSION,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "metadata-url",
				Value: "http://metadata/2016-07-29",
			},
			&cli.StringFlag{
				Name:  "conntracksync-interval",
				Usage: fmt.Sprintf("Customize the interval of conntracksync in seconds (default: %v)", conntracksync.DefaultSyncInterval),
				Value: "",
			},
			&cli.StringFlag{
				Name:  "routesync-interval",
				Usage: fmt.Sprintf("Customize the interval of routesync in seconds (default: %v)", routesync.DefaultSyncInterval),
				Value: "",
			},
			&cli.StringFlag{
				Name:  "arpsync-interval",
				Usage: fmt.Sprintf("Customize the interval of arpsync in seconds (default: %v)", arpsync.DefaultSyncInterval),
				Value: "",
			},
			&cli.BoolFlag{
				Name:  "debug",
				Usage: "Turn on debug logging",
			},
		},
		Action: run,
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		logrus.Fatal(err)
	}
}

func run(_ context.Context, c *cli.Command) error {
	if c.Bool("debug") {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if err := routesync.Watch(c.String("routesync-interval")); err != nil {
		logrus.Errorf("Failed to start routesync: %v", err)
		return err
	}

	dClient, err := client.New(client.FromEnv)
	if err != nil {
		return err
	}

	reaper.CheckMetadata(dClient, true)

	logrus.Infof("Waiting for metadata")
	mClient, err := metadata.NewClientAndWait(c.String("metadata-url"))
	if err != nil {
		return fmt.Errorf("create metadata client: %w", err)
	}

	macsync.SyncMACAddresses(mClient, dClient)

	manager, err := network.NewManager(dClient)
	if err != nil {
		return err
	}

	if err := reaper.Watch(dClient, mClient); err != nil {
		logrus.Errorf("Failed to start unmanaged container reaper: %v", err)
	}

	if err := hostports.Watch(mClient, dClient); err != nil {
		logrus.Errorf("Failed to start host ports configuration: %v", err)
	}

	if err := hostnat.Watch(mClient, dClient); err != nil {
		logrus.Errorf("Failed to start host nat configuration: %v", err)
	}

	if err := conntracksync.Watch(c.String("conntracksync-interval"), mClient, dClient); err != nil {
		logrus.Errorf("Failed to start conntracksync: %v", err)
	}

	if err := cniconf.Watch(mClient, dClient); err != nil {
		logrus.Errorf("Failed to start cni config: %v", err)
	}

	if err := arpsync.Watch(c.String("arpsync-interval"), mClient, dClient); err != nil {
		logrus.Errorf("Failed to start arpsync: %v", err)
	}

	binWatcher := binexec.Watch(mClient, dClient)

	if err := events.Watch(100, dClient, manager, binWatcher); err != nil {
		return err
	}

	<-make(chan struct{})
	return nil
}
