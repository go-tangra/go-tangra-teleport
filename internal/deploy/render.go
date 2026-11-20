// Package deploy is US6 (FR-030, FR-031, research D14): the deployment
// wizard for a new Teleport Community Edition cluster. A draft holds the
// wizard inputs; the artifacts (teleport.yaml, a version-pinned install.sh,
// the tangra-manager role, the setup commands and a checklist) are rendered
// on request from embedded text/template files and never stored; the
// prerequisite checks (dns_apex, dns_wildcard, tls_443) go only through
// netguard (research D12, SR-003), at most once per 10 s per draft.
//
// Inputs are validated strictly before anything is rendered: an RFC 1123
// domain, an e-mail address, a version x.y.z, a username and POSIX logins,
// each limited to letters, digits and . _ @ - (and @ only where it belongs),
// so no value can carry shell, YAML or Markdown syntax. The templates still
// quote every value for its context (shq, yq) as defence in depth. Nothing
// is executed remotely (spec assumption).
package deploy

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// Artifacts lists the artifact names in wizard order (contracts/http-api.md).
var Artifacts = []string{"teleport.yaml", "install.sh", "tangra-manager-role.yaml", "setup-commands.txt", "checklist.md"}

// ErrUnknownArtifact refuses a name outside Artifacts (not_found).
var ErrUnknownArtifact = errors.New("deploy: unknown artifact")

// Bounds.
const (
	MaxLogins    = 32
	maxDomain    = 253
	maxEmail     = 254
	maxUsername  = 64
	maxVersionNo = 4 // digits per version component
)

var (
	label    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	numeric  = regexp.MustCompile(`^[0-9]+$`)
	local    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$`)
	version  = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)
	username = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	login    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]{0,31}$`)
	bare     = regexp.MustCompile(`^[A-Za-z0-9._@,:/-]+$`)
)

//go:embed templates/*.tmpl
var templateFS embed.FS

var templates = template.Must(template.New("deploy").Option("missingkey=error").Funcs(template.FuncMap{
	"shq":  shellQuote,
	"yq":   yamlQuote,
	"join": strings.Join,
}).ParseFS(templateFS, "templates/*.tmpl"))

// Input is what the artifacts are rendered from (data-model deployment_draft).
type Input struct {
	Domain          string
	CertMode        string // repo.CertACME | repo.CertOwn
	ACMEEmail       string // required for acme, empty for own_cert
	TeleportVersion string
	AdminUsername   string
	AdminLogins     []string
}

// ACME reports the ACME certificate mode (templates).
func (in Input) ACME() bool { return in.CertMode == repo.CertACME }

func invalid(field, msg string) error { return &clusters.FieldError{Field: field, Msg: msg} }

// validDomain checks an RFC 1123 FQDN of at least two labels whose top-level
// label is not numeric (so no IP address).
func validDomain(d string) bool {
	if d == "" || len(d) > maxDomain {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 || numeric.MatchString(labels[len(labels)-1]) {
		return false
	}
	for _, l := range labels {
		if !label.MatchString(l) {
			return false
		}
	}
	return true
}

func validEmail(e string) (string, bool) {
	if len(e) > maxEmail {
		return "", false
	}
	user, host, ok := strings.Cut(e, "@")
	host = strings.ToLower(host)
	if !ok || !local.MatchString(user) || strings.Contains(user, "..") || !validDomain(host) {
		return "", false
	}
	return user + "@" + host, true
}

// Validate checks and normalizes in (lower-case domain, de-duplicated
// logins). Every refusal is a clusters.FieldError naming the field.
func Validate(in Input) (Input, error) {
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	if !validDomain(in.Domain) {
		return Input{}, invalid("domain", "must be a fully qualified domain name such as teleport.example.com (letters, digits and -)")
	}
	switch in.CertMode {
	case repo.CertACME:
		e, ok := validEmail(strings.TrimSpace(in.ACMEEmail))
		if !ok {
			return Input{}, invalid("acme_email", "must be an e-mail address (letters, digits and . _ - before the @)")
		}
		in.ACMEEmail = e
	case repo.CertOwn:
		if in.ACMEEmail != "" {
			return Input{}, invalid("acme_email", "is only used with an ACME certificate")
		}
	default:
		return Input{}, invalid("cert_mode", "must be acme or own_cert")
	}
	if !version.MatchString(in.TeleportVersion) {
		return Input{}, invalid("teleport_version", "must be a release version such as 19.1.2")
	}
	if len(in.AdminUsername) > maxUsername || !username.MatchString(in.AdminUsername) {
		return Input{}, invalid("admin_username", "must be 1 to 64 letters, digits or . _ @ - and start with a letter or digit")
	}
	if len(in.AdminLogins) == 0 || len(in.AdminLogins) > MaxLogins {
		return Input{}, invalid("admin_logins", "must list 1 to "+strconv.Itoa(MaxLogins)+" logins")
	}
	logins := make([]string, 0, len(in.AdminLogins))
	for _, l := range in.AdminLogins {
		if !login.MatchString(l) {
			return Input{}, invalid("admin_logins", "each login must be 1 to 32 letters, digits or . _ - and start with a letter or _")
		}
		if !slices.Contains(logins, l) {
			logins = append(logins, l)
		}
	}
	in.AdminLogins = logins
	return in, nil
}

// Render validates in and renders one artifact.
func Render(name string, in Input) ([]byte, error) {
	if !slices.Contains(Artifacts, name) {
		return nil, ErrUnknownArtifact
	}
	in, err := Validate(in)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := templates.ExecuteTemplate(&b, name+".tmpl", in); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// shellQuote leaves a value of the safe alphabet as it is and single-quotes
// anything else for a POSIX shell.
func shellQuote(s string) string {
	if bare.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// yamlQuote renders s as a YAML double-quoted scalar (JSON strings are YAML).
func yamlQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
