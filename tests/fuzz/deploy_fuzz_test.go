package fuzz

import (
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/deploy"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// safe is the only alphabet a validated wizard value may use: nothing a
// shell, YAML or Markdown would interpret.
var safe = regexp.MustCompile(`^[A-Za-z0-9._@-]*$`)

// FuzzDeployInput: the wizard inputs are tenant input rendered into a shell
// script and a YAML file. Whatever the input, Validate either refuses it or
// returns values of the safe alphabet, and then every artifact renders and
// teleport.yaml parses with the cluster name it was given.
func FuzzDeployInput(f *testing.F) {
	f.Add("tp.example.test", "acme", "ops@example.test", "19.1.2", "admin", "root,ubuntu")
	f.Add("teleport.corp.example", "own_cert", "", "18.7.0", "alice@corp.example", "ec2-user")
	f.Add("x$(id).example.test", "acme", "o'ps@example.test", "19.1.2\n", "a;rm", "-oProxyCommand=x")
	f.Add("TP.EXAMPLE.TEST", "acme", "ops@EXAMPLE.test", "1.2.3", "a`b`", "root|id")
	f.Add("a.b", "acme", "a@b.c", "0.0.0", "x", "_")
	f.Fuzz(func(t *testing.T, domain, mode, email, version, user, logins string) {
		in := deploy.Input{Domain: domain, CertMode: mode, ACMEEmail: email, TeleportVersion: version, AdminUsername: user,
			AdminLogins: strings.Split(logins, ",")}
		out, err := deploy.Validate(in)
		if err != nil {
			if _, rerr := deploy.Render("install.sh", in); rerr == nil {
				t.Fatal("an invalid input rendered")
			}
			return
		}
		for _, v := range append([]string{out.Domain, out.ACMEEmail, out.TeleportVersion, out.AdminUsername}, out.AdminLogins...) {
			if !safe.MatchString(v) {
				t.Fatalf("validated value %q outside the safe alphabet", v)
			}
		}
		if out.CertMode != repo.CertACME && out.CertMode != repo.CertOwn {
			t.Fatalf("cert mode %q", out.CertMode)
		}
		for _, name := range deploy.Artifacts {
			if _, err := deploy.Render(name, out); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		cfg, _ := deploy.Render("teleport.yaml", out)
		var doc struct {
			Auth struct {
				ClusterName string `yaml:"cluster_name"`
			} `yaml:"auth_service"`
		}
		if err := yaml.Unmarshal(cfg, &doc); err != nil || doc.Auth.ClusterName != out.Domain {
			t.Fatalf("teleport.yaml: %v %q", err, doc.Auth.ClusterName)
		}
	})
}
