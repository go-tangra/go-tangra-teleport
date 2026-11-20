package clusters_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

func TestGuardErrors(t *testing.T) {
	var err error = &clusters.GuardError{Guard: clusters.GuardPresetRole, Msg: "built-in"}
	if !errors.Is(err, clusters.ErrRefused) || errors.Is(err, clusters.ErrInvalid) || !strings.Contains(err.Error(), "preset_role") {
		t.Fatalf("guard error %v", err)
	}
	if clusters.ReasonOf(err) != clusters.GuardPresetRole || clusters.ReasonOf(clusters.ErrUnsupportedVersion) != "unsupported_version" {
		t.Fatal("audit reasons")
	}
	f := teleportapi.NewFake()
	f.Users = []teleportapi.User{{Name: "tangra-mgmt", Roles: []string{"tangra-manager"}}}
	c := repo.Cluster{CredentialIdentity: "tangra-mgmt"}
	if u, err := clusters.ManagementIdentity(context.Background(), c, f); err != nil || u.Roles[0] != "tangra-manager" {
		t.Fatalf("identity %+v %v", u, err)
	}
	if !clusters.IsManagementIdentity(c, "tangra-mgmt") || clusters.IsManagementIdentity(repo.Cluster{}, "") {
		t.Fatal("IsManagementIdentity")
	}
	var g *clusters.GuardError
	if _, err := clusters.ManagementIdentity(context.Background(), repo.Cluster{}, f); !errors.As(err, &g) || g.Guard != clusters.GuardSelfIdentity {
		t.Fatalf("unknown identity must refuse: %v", err)
	}
}

func TestNames(t *testing.T) {
	for _, ok := range []string{"alice", "a.b-c_d@example.com", "ec2-user", "ns:role", "x"} {
		if err := clusters.ValidName("name", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-a", "a b", "a/b", "{{internal.logins}}", "é", strings.Repeat("a", 129), "a\x00"} {
		if err := clusters.ValidName("name", bad); !errors.Is(err, clusters.ErrInvalid) {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, err := clusters.ValidNames("roles", []string{" access", "access", "editor"}, 1, 2); err != nil || len(got) != 2 {
		t.Fatalf("dedupe %v %v", got, err)
	}
	if _, err := clusters.ValidNames("roles", nil, 1, 2); err == nil {
		t.Fatal("min")
	}
	if _, err := clusters.ValidNames("logins", []string{"a", "b", "c"}, 0, 2); err == nil {
		t.Fatal("max")
	}
	if s, err := clusters.ValidText("reason", "  why  ", 10); err != nil || s != "why" {
		t.Fatalf("text %q %v", s, err)
	}
}
