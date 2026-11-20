package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/pkg/teleportmanifest"
)

// The release step lists the permissions from the module's own manifest.
func TestCataloguePermissions(t *testing.T) {
	var out bytes.Buffer
	if code := cataloguePermissions(&out); code != 0 {
		t.Fatal(code)
	}
	var perms []string
	if err := json.Unmarshal(out.Bytes(), &perms); err != nil {
		t.Fatal(err)
	}
	if strings.Join(perms, ",") != strings.Join(teleportmanifest.PermissionRefs(), ",") || len(perms) == 0 {
		t.Fatalf("%v", perms)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestCataloguePermissionsWriteFailure(t *testing.T) {
	if cataloguePermissions(failWriter{}) != 1 {
		t.Fatal("a write failure succeeded")
	}
}
