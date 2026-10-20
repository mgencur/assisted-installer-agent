package apivip_check

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openshift/assisted-service/models"
	"github.com/sirupsen/logrus"
)

const proxyTestScenarioEnv = "ASSISTED_INSTALLER_AGENT_PROXY_TEST_SCENARIO"
const proxyTestHostname = "ignition.invalid"

func TestDownloadIgnitionWithHTTPSProxyAndCustomCA(t *testing.T) {
	if scenario := os.Getenv(proxyTestScenarioEnv); scenario != "" {
		runProxyTestScenario(t, scenario)
		return
	}

	// ProxyFromEnvironment reads the environment once per process. Run each
	// scenario separately so it sees the proxy settings configured below.
	for _, scenario := range []string{"proxy", "no_proxy"} {
		t.Run(scenario, func(t *testing.T) {
			//nolint:gosec // G204: re-execute the running test binary with fixed flags.
			cmd := exec.Command(os.Args[0], "-test.run=^TestDownloadIgnitionWithHTTPSProxyAndCustomCA$", "-test.timeout=1m")
			cmd.Env = append(os.Environ(), proxyTestScenarioEnv+"="+scenario)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("proxy scenario failed: %v\n%s", err, output)
			}
		})
	}
}

func runProxyTestScenario(t *testing.T, scenario string) {
	serverConfig, caPEM, err := certsetup()
	if err != nil {
		t.Fatal(err)
	}
	server, err := httpsServerMock(serverConfig, ignitionMock)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	targetHost := net.JoinHostPort(proxyTestHostname, port)
	targetURL := "https://" + targetHost

	var connectCount atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connectCount.Add(1)
		if r.Method != http.MethodConnect || r.Host != targetHost {
			t.Errorf("unexpected proxy request: %s %s", r.Method, r.Host)
			http.Error(w, "unexpected proxy request", http.StatusBadRequest)
			return
		}

		upstream, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			t.Errorf("connect to ignition server: %v", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			t.Errorf("hijack proxy connection: %v", err)
			return
		}
		if _, err := fmt.Fprint(buffered, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			client.Close()
			upstream.Close()
			return
		}
		if err := buffered.Flush(); err != nil {
			client.Close()
			upstream.Close()
			return
		}

		go func() {
			_, _ = io.Copy(upstream, buffered)
			upstream.Close()
			client.Close()
		}()
		_, _ = io.Copy(client, upstream)
		client.Close()
		upstream.Close()
	}))
	defer proxy.Close()

	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	if scenario == "no_proxy" {
		t.Setenv("NO_PROXY", proxyTestHostname)
	} else if scenario != "proxy" {
		t.Fatalf("unknown proxy scenario %q", scenario)
	}

	encodedCA := base64.StdEncoding.EncodeToString(caPEM)
	stdout, stderr, exitCode := CheckAPIConnectivity(getRequestStr(&targetURL, false, &encodedCA, nil), logrus.New())
	var response models.APIVipConnectivityResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("invalid response %q: %v", stdout, err)
	}
	if exitCode != 0 {
		t.Errorf("unexpected exit code %d", exitCode)
	}

	switch scenario {
	case "proxy":
		if !response.IsSuccess || stderr != "" {
			t.Errorf("ignition download through proxy failed: %s", response.DownloadError)
		}
		if connectCount.Load() != 1 {
			t.Errorf("expected one CONNECT request, got %d", connectCount.Load())
		}
	case "no_proxy":
		if response.IsSuccess || !strings.Contains(response.DownloadError, "request failed") {
			t.Errorf("expected direct download to fail, got success=%t, error=%q", response.IsSuccess, response.DownloadError)
		}
		if connectCount.Load() != 0 {
			t.Errorf("NO_PROXY should bypass the proxy, got %d CONNECT requests", connectCount.Load())
		}
	}
}
