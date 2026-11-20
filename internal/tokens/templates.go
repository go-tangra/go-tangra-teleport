package tokens

import (
	"errors"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// Install-command templates (research D9). Servers join with Teleport's own
// install script served by the proxy; the other types get a teleport.yaml
// snippet and the `teleport <type> start` arguments (kube and desktop run
// from the snippet). Every value that reaches the shell is single-quoted
// (ShellQuote) and the snippet is YAML-encoded, so a registered proxy
// address can never inject a command. Example names, URIs and hosts are
// placeholders the operator edits.

// ConfigPath is where the snippet is meant to be saved.
const ConfigPath = "/etc/teleport.yaml"

// errType refuses an unknown resource type.
var errType = errors.New("tokens: unknown resource type")

// Install is the rendered command and teleport.yaml snippet.
type Install struct {
	Command string
	Config  string
}

// ShellQuote single-quotes s for a POSIX shell.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// webAddr is the proxy address as a URL host: the default port 443 is
// implied by https.
func webAddr(proxy string) string { return strings.TrimSuffix(proxy, ":443") }

type joinParams struct {
	Method    string `yaml:"method"`
	TokenName string `yaml:"token_name"`
}

type teleportSection struct {
	ProxyServer string     `yaml:"proxy_server"`
	JoinParams  joinParams `yaml:"join_params"`
}

type toggle struct {
	Enabled bool `yaml:"enabled"`
}

type exampleApp struct {
	Name string `yaml:"name"`
	URI  string `yaml:"uri"`
}

type exampleDB struct {
	Name     string `yaml:"name"`
	Protocol string `yaml:"protocol"`
	URI      string `yaml:"uri"`
}

type exampleHost struct {
	Addr string `yaml:"addr"`
}

type service struct {
	Enabled        bool          `yaml:"enabled"`
	Apps           []exampleApp  `yaml:"apps,omitempty"`
	Databases      []exampleDB   `yaml:"databases,omitempty"`
	KubeconfigFile string        `yaml:"kubeconfig_file,omitempty"`
	StaticHosts    []exampleHost `yaml:"static_hosts,omitempty"`
}

type config struct {
	Version  string          `yaml:"version"`
	Teleport teleportSection `yaml:"teleport"`
	Auth     toggle          `yaml:"auth_service"`
	Proxy    toggle          `yaml:"proxy_service"`
	SSH      toggle          `yaml:"ssh_service"`
	App      *service        `yaml:"app_service,omitempty"`
	DB       *service        `yaml:"db_service,omitempty"`
	Kube     *service        `yaml:"kubernetes_service,omitempty"`
	Desktop  *service        `yaml:"windows_desktop_service,omitempty"`
}

// Placeholders of the generated configuration.
const (
	exampleAppName = "example-app"
	exampleAppURI  = "http://localhost:8080"
	exampleDBName  = "example-db"
	exampleDBURI   = "localhost:5432"
)

// Render builds the install command and config snippet for kind.
func Render(kind, proxy, token string) (Install, error) {
	cfg := config{Version: "v3", Teleport: teleportSection{ProxyServer: proxy, JoinParams: joinParams{Method: "token", TokenName: token}}}
	start := "sudo teleport start --config=" + ConfigPath
	var cmd string
	switch kind {
	case repo.KindNode:
		cfg.SSH.Enabled = true
		cmd = "curl -fsSL " + ShellQuote("https://"+webAddr(proxy)+"/scripts/"+token+"/install-node.sh") + " | sudo bash"
	case repo.KindApp:
		cfg.App = &service{Enabled: true, Apps: []exampleApp{{Name: exampleAppName, URI: exampleAppURI}}}
		cmd = "sudo teleport app start --token=" + ShellQuote(token) + " --proxy=" + ShellQuote(proxy) +
			" --name=" + exampleAppName + " --uri=" + ShellQuote(exampleAppURI)
	case repo.KindDB:
		cfg.DB = &service{Enabled: true, Databases: []exampleDB{{Name: exampleDBName, Protocol: "postgres", URI: exampleDBURI}}}
		cmd = "sudo teleport db start --token=" + ShellQuote(token) + " --proxy=" + ShellQuote(proxy) +
			" --name=" + exampleDBName + " --protocol=postgres --uri=" + ShellQuote(exampleDBURI)
	case repo.KindKube:
		cfg.Kube = &service{Enabled: true, KubeconfigFile: "/etc/teleport/kubeconfig"}
		cmd = start
	case repo.KindDesktop:
		cfg.Desktop = &service{Enabled: true, StaticHosts: []exampleHost{{Addr: "desktop.example.internal"}}}
		cmd = start
	default:
		return Install{}, errType
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return Install{}, err
	}
	return Install{Command: cmd, Config: string(b)}, nil
}
