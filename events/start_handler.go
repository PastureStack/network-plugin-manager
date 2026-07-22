package events

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"strings"

	"github.com/fsouza/go-dockerclient"
	"github.com/rancher/event-subscriber/locks"
	log "github.com/sirupsen/logrus"
)

const (
	MetadataNameserver     = "169.254.169.250"
	PlatformDomain         = "pasture.internal"
	LegacyDNSLabel         = "io.rancher.container.dns"
	LegacyDNSPriorityLabel = "io.rancher.container.dns.priority"
	LegacyNetworkLabel     = "io.rancher.container.network"
	CNILabel               = "io.rancher.cni.network"
)

type StartHandler struct {
	Client SimpleDockerClient
}

func getDNSSearch(container *docker.Container) []string {
	var defaultDomains []string
	var svcNameSpace string
	var stackNameSpace string

	//from labels - for upgraded systems
	if container.Config.Labels != nil {
		if value, ok := container.Config.Labels["io.rancher.stack_service.name"]; ok {
			parts := strings.SplitN(value, "/", 2)
			if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
				svc := strings.ToLower(parts[1])
				stack := strings.ToLower(parts[0])
				svcNameSpace = svc + "." + stack + "." + PlatformDomain
				stackNameSpace = stack + "." + PlatformDomain
				defaultDomains = append(defaultDomains, svcNameSpace, stackNameSpace)
			}
		}
	}

	//from search domains
	if container.HostConfig.DNSSearch != nil {
		for _, domain := range container.HostConfig.DNSSearch {
			if domain != svcNameSpace && domain != stackNameSpace {
				defaultDomains = append(defaultDomains, domain)
			}
		}
	}

	defaultDomains = append(defaultDomains, PlatformDomain)

	log.Debugf("defaultDomains: %v", defaultDomains)
	return defaultDomains
}

func setupResolvConf(container *docker.Container) error {
	log.Debugf("Setting up resolver configuration for container %s", container.ID)
	if container.ResolvConfPath == "/etc/resolv.conf" {
		// Don't shoot ourself in the foot and change our own DNS
		log.Debugf("resolv.conf already set for container: %v, skipping", container.ID)
		return nil
	}

	input, err := os.Open(container.ResolvConfPath)
	if err != nil {
		return err
	}

	defer input.Close()

	var buffer bytes.Buffer
	scanner := bufio.NewScanner(input)
	searchSet := false
	nameserverSet := false
	for scanner.Scan() {
		text := scanner.Text()

		if strings.Contains(text, MetadataNameserver) {
			nameserverSet = true
		} else if strings.HasPrefix(text, "nameserver") {
			text = "# " + text
		}

		if strings.HasPrefix(text, "search") {
			domainsToBeAdded := []string{}
			for _, domain := range getDNSSearch(container) {
				if strings.Contains(text, " "+domain) {
					continue
				}
				domainsToBeAdded = append(domainsToBeAdded, domain)
			}

			if container.Config.Labels[LegacyDNSPriorityLabel] == "service_last" {
				text = text + " " + strings.Join(domainsToBeAdded, " ")
			} else {
				text = strings.Replace(text, "search", "search "+strings.Join(domainsToBeAdded, " "), 1)
			}
			log.Debugf("text: %v", text)
			searchSet = true
		}

		if _, err := buffer.Write([]byte(text)); err != nil {
			return err
		}

		if _, err := buffer.Write([]byte("\n")); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if !searchSet {
		buffer.Write([]byte("search " + strings.ToLower(strings.Join(getDNSSearch(container), " "))))
		buffer.Write([]byte("\n"))
	}

	if !nameserverSet {
		buffer.Write([]byte("nameserver "))
		buffer.Write([]byte(MetadataNameserver))
		buffer.Write([]byte("\n"))
	}

	return ioutil.WriteFile(container.ResolvConfPath, buffer.Bytes(), 0644)
}

func (h *StartHandler) Handle(event *docker.APIEvents) error {
	// Note: event.ID == container's ID
	lock := locks.Lock("start." + event.ID)
	if lock == nil {
		log.Debugf("Container locked. Can't run StartHandler. ID: [%s]", event.ID)
		return nil
	}
	defer lock.Unlock()

	c, err := h.Client.InspectContainer(event.ID)
	if err != nil {
		return err
	}

	if !c.State.Running {
		log.Infof("Container [%s] not running. Can't setup resolv.conf.", c.ID)
		return nil
	}

	if c.Config.Labels[LegacyDNSLabel] == "false" {
		return nil
	}

	if c.Config.Labels[CNILabel] != "" || c.Config.Labels[LegacyDNSLabel] == "true" ||
		c.Config.Labels[LegacyNetworkLabel] == "true" {
		log.Infof("Setting up resolv.conf for ContainerId [%s]", event.ID)
		return setupResolvConf(c)
	}

	return nil
}
