package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	connectionDeadline = 20 * time.Second
	requestTimeout     = 15 * time.Second
	maxResponseBytes   = 32 << 20
)

type Client interface {
	OnChangeWithError(int, func(string)) error
	OnChange(int, func(string))
	SendRequest(string) ([]byte, error)
	GetVersion() (string, error)
	GetSelfHost() (Host, error)
	GetSelfContainer() (Container, error)
	GetSelfServiceByName(string) (Service, error)
	GetSelfService() (Service, error)
	GetSelfStack() (Stack, error)
	GetServices() ([]Service, error)
	GetStacks() ([]Stack, error)
	GetContainers() ([]Container, error)
	GetServiceContainers(string, string) ([]Container, error)
	GetHosts() ([]Host, error)
	GetHost(string) (Host, error)
	GetNetworks() ([]Network, error)
}

type httpClient struct {
	baseURL      *url.URL
	forwardedFor string
	client       *http.Client
	initErr      error
}

func NewClient(rawURL string) Client {
	client, err := newHTTPClient(rawURL, "")
	if err != nil {
		return &httpClient{initErr: err}
	}
	return client
}

func NewClientAndWait(rawURL string) (Client, error) {
	return NewClientWithIPAndWait(rawURL, "")
}

func NewClientWithIPAndWait(rawURL, forwardedFor string) (Client, error) {
	client, err := newHTTPClient(rawURL, forwardedFor)
	if err != nil {
		return nil, err
	}
	if err := waitForConnection(client); err != nil {
		return nil, err
	}
	return client, nil
}

func newHTTPClient(rawURL, forwardedFor string) (*httpClient, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("invalid metadata URL")
	}
	if (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" {
		return nil, errors.New("metadata URL must use HTTP or HTTPS and include a host")
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("metadata URL must not contain credentials, a query, or a fragment")
	}
	if forwardedFor != "" && net.ParseIP(forwardedFor) == nil {
		return nil, errors.New("forwarded metadata address is not an IP address")
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.IdleConnTimeout = 30 * time.Second

	client := &http.Client{Transport: transport}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		origin := via[0].URL
		if !strings.EqualFold(request.URL.Scheme, origin.Scheme) || !strings.EqualFold(request.URL.Host, origin.Host) {
			return errors.New("metadata redirect changed origin")
		}
		if len(via) >= 5 {
			return errors.New("too many metadata redirects")
		}
		return nil
	}

	return &httpClient{
		baseURL:      baseURL,
		forwardedFor: forwardedFor,
		client:       client,
	}, nil
}

func waitForConnection(client *httpClient) error {
	deadline := time.Now().Add(connectionDeadline)
	delay := time.Second
	var lastErr error
	for {
		if _, err := client.GetVersion(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().Add(delay).After(deadline) {
			return fmt.Errorf("metadata service did not become ready: %w", lastErr)
		}
		time.Sleep(delay)
		if delay < 4*time.Second {
			delay *= 2
		}
	}
}

func (client *httpClient) endpoint(path string) (*url.URL, error) {
	if client.initErr != nil {
		return nil, client.initErr
	}
	reference, err := url.Parse(path)
	if err != nil || reference.IsAbs() || reference.Host != "" || !strings.HasPrefix(reference.Path, "/") {
		return nil, errors.New("invalid metadata request path")
	}
	for _, segment := range strings.Split(reference.EscapedPath(), "/") {
		if segment == ".." || strings.EqualFold(segment, "%2e%2e") {
			return nil, errors.New("metadata request path contains traversal")
		}
	}
	target := *client.baseURL
	target.Path = client.baseURL.Path + reference.Path
	target.RawPath = ""
	target.RawQuery = reference.RawQuery
	return &target, nil
}

func (client *httpClient) sendRequest(path string, timeout time.Duration) ([]byte, error) {
	target, err := client.endpoint(path)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, errors.New("could not create metadata request")
	}
	request.Header.Set("Accept", "application/json")
	if client.forwardedFor != "" {
		request.Header.Set("X-Forwarded-For", client.forwardedFor)
	}

	response, err := client.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("metadata request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata request returned HTTP %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, errors.New("could not read metadata response")
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("metadata response exceeded size limit")
	}
	return body, nil
}

func (client *httpClient) SendRequest(path string) ([]byte, error) {
	return client.sendRequest(path, requestTimeout)
}

func (client *httpClient) decode(path string, destination interface{}) error {
	body, err := client.SendRequest(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, destination); err != nil {
		return errors.New("metadata response was not valid JSON")
	}
	return nil
}

func (client *httpClient) GetVersion() (string, error) {
	var version string
	if err := client.decode("/version", &version); err != nil {
		return "", err
	}
	return version, nil
}

func (client *httpClient) GetSelfHost() (Host, error) {
	var result Host
	return result, client.decode("/self/host", &result)
}

func (client *httpClient) GetSelfContainer() (Container, error) {
	var result Container
	return result, client.decode("/self/container", &result)
}

func (client *httpClient) GetSelfServiceByName(name string) (Service, error) {
	var result Service
	return result, client.decode("/self/stack/services/"+url.PathEscape(name), &result)
}

func (client *httpClient) GetSelfService() (Service, error) {
	var result Service
	return result, client.decode("/self/service", &result)
}

func (client *httpClient) GetSelfStack() (Stack, error) {
	var result Stack
	return result, client.decode("/self/stack", &result)
}

func (client *httpClient) GetServices() ([]Service, error) {
	var result []Service
	return result, client.decode("/services", &result)
}

func (client *httpClient) GetStacks() ([]Stack, error) {
	var result []Stack
	return result, client.decode("/stacks", &result)
}

func (client *httpClient) GetContainers() ([]Container, error) {
	var result []Container
	return result, client.decode("/containers", &result)
}

func (client *httpClient) GetServiceContainers(serviceName, stackName string) ([]Container, error) {
	containers, err := client.GetContainers()
	if err != nil {
		return nil, err
	}
	result := make([]Container, 0)
	for _, container := range containers {
		if container.ServiceName == serviceName && container.StackName == stackName {
			result = append(result, container)
		}
	}
	return result, nil
}

func (client *httpClient) GetHosts() ([]Host, error) {
	var result []Host
	return result, client.decode("/hosts", &result)
}

func (client *httpClient) GetHost(uuid string) (Host, error) {
	hosts, err := client.GetHosts()
	if err != nil {
		return Host{}, err
	}
	for _, host := range hosts {
		if host.UUID == uuid {
			return host, nil
		}
	}
	return Host{}, errors.New("metadata host was not found")
}

func (client *httpClient) GetNetworks() ([]Network, error) {
	var result []Network
	return result, client.decode("/networks", &result)
}

func (client *httpClient) waitVersion(maxWait int, version string) (string, error) {
	if maxWait < 1 {
		maxWait = 1
	}
	values := url.Values{}
	values.Set("wait", "true")
	values.Set("value", version)
	values.Set("maxWait", strconv.Itoa(maxWait))
	body, err := client.sendRequest("/version?"+values.Encode(), time.Duration(maxWait+10)*time.Second)
	if err != nil {
		return "", err
	}
	var next string
	if err := json.Unmarshal(body, &next); err != nil {
		return "", errors.New("metadata version response was not valid JSON")
	}
	return next, nil
}

func (client *httpClient) OnChangeWithError(intervalSeconds int, callback func(string)) error {
	if callback == nil {
		return errors.New("metadata change callback is nil")
	}
	version := "init"
	for {
		next, err := client.waitVersion(intervalSeconds, version)
		if err != nil {
			return err
		}
		if next != version {
			version = next
			callback(next)
		}
	}
}

func (client *httpClient) OnChange(intervalSeconds int, callback func(string)) {
	if intervalSeconds < 1 {
		intervalSeconds = 1
	}
	for {
		if err := client.OnChangeWithError(intervalSeconds, callback); err != nil {
			logrus.Errorf("Metadata change stream failed: %v", err)
		}
		time.Sleep(time.Duration(intervalSeconds) * time.Second)
	}
}
