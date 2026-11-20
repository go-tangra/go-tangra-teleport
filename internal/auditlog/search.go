// Package auditlog is the read side of US4 (FR-021, FR-022, FR-024): live
// Teleport audit-event and recorded-session search, the normalization of
// Teleport events into one bounded shape, session playback links, and the
// module's own audit trail.
//
// Searches are served live from the cluster (research D8): the window is
// required and at most 31 days, a page holds at most 200 events, and
// Teleport's opaque `next` key is handed back unchanged. Only allow-listed
// event types are searched (EventTypes); an empty type filter means all of
// them. A failed login is its own normalized type (user.login.failure) so
// alert rules and filters can name it. The user and resource filters, and
// the split of a Teleport type into normalized types, apply to the events
// read; when they drop events, further Teleport pages are read (each sized
// to what is still missing, so `next` stays exact) up to maxReads per call.
//
// Normalized fields are bounded and stripped of control characters; `raw`
// is a JSON object of at most 16 KiB (a larger event keeps only its
// top-level scalar fields, each bounded, and is marked "truncated"; an
// event that is not a JSON object is {}). Teleport-supplied
// text is data: the UI renders it as text only (SR-004).
package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Bounds (contracts/http-api.md, Audit and alerts).
const (
	MaxWindow    = 31 * 24 * time.Hour
	MaxLimit     = 200
	DefaultLimit = 50
	MaxRaw       = 16 << 10
	MaxTypes     = 32
	maxFilter    = 128
	maxText      = 256
	maxReads     = 5
	maxPeople    = 32
)

// Normalized event types: the allow-list.
const (
	TypeLogin               = "user.login"
	TypeLoginFailure        = "user.login.failure"
	TypeUserCreate          = "user.create"
	TypeUserUpdate          = "user.update"
	TypeUserDelete          = "user.delete"
	TypePasswordChange      = "user.password_change"
	TypeResetTokenCreate    = "reset_password_token.create"
	TypeSessionStart        = "session.start"
	TypeSessionEnd          = "session.end"
	TypeSessionJoin         = "session.join"
	TypeSessionLeave        = "session.leave"
	TypeExec                = "exec"
	TypeAppSessionStart     = "app.session.start"
	TypeDBSessionStart      = "db.session.start"
	TypeDesktopSessionStart = "windows.desktop.session.start"
	TypeRoleCreated         = "role.created"
	TypeRoleUpdated         = "role.updated"
	TypeRoleDeleted         = "role.deleted"
	TypeLockCreated         = "lock.created"
	TypeLockDeleted         = "lock.deleted"
	TypeAccessRequestCreate = "access_request.create"
	TypeAccessRequestReview = "access_request.review"
	TypeCertCreate          = "cert.create"
)

// EventTypes is the allow-list of normalized event types (sorted), for
// search filters and alert rules.
var EventTypes = func() []string {
	out := []string{TypeLogin, TypeLoginFailure, TypeUserCreate, TypeUserUpdate, TypeUserDelete, TypePasswordChange,
		TypeResetTokenCreate, TypeSessionStart, TypeSessionEnd, TypeSessionJoin, TypeSessionLeave, TypeExec,
		TypeAppSessionStart, TypeDBSessionStart, TypeDesktopSessionStart, TypeRoleCreated, TypeRoleUpdated, TypeRoleDeleted,
		TypeLockCreated, TypeLockDeleted, TypeAccessRequestCreate, TypeAccessRequestReview, TypeCertCreate}
	sort.Strings(out)
	return out
}()

// Allowed reports whether t is an allow-listed normalized type.
func Allowed(t string) bool {
	_, ok := slices.BinarySearch(EventTypes, t)
	return ok
}

// teleportType is the Teleport event type a normalized type is read from.
func teleportType(t string) string {
	if t == TypeLoginFailure {
		return TypeLogin
	}
	return t
}

// TeleportTypes returns the Teleport event types to search for the
// normalized types (none: every allow-listed type), sorted and unique.
func TeleportTypes(types []string) []string {
	if len(types) == 0 {
		types = EventTypes
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range types {
		if tt := teleportType(t); !seen[tt] {
			seen[tt] = true
			out = append(out, tt)
		}
	}
	sort.Strings(out)
	return out
}

// codes names the event type of the main Teleport event codes, for events
// that arrive without a type.
var codes = map[string]string{
	"T1000I": TypeLogin, "T1001I": TypeLogin, "T1000W": TypeLoginFailure, "T1001W": TypeLoginFailure,
	"T1002I": TypeUserCreate, "T1003I": TypeUserUpdate, "T1004I": TypeUserDelete, "T1005I": TypePasswordChange,
	"T6000I": TypeResetTokenCreate,
	"T2000I": TypeSessionStart, "T2001I": TypeSessionJoin, "T2003I": TypeSessionLeave, "T2004I": TypeSessionEnd,
	"T2007I": TypeAppSessionStart, "TDB00I": TypeDBSessionStart, "TDB00W": TypeDBSessionStart,
	"T3002I": TypeExec, "T3002E": TypeExec,
	"T9000I": TypeRoleCreated, "T9001I": TypeRoleDeleted, "T9002I": TypeRoleUpdated,
	"TLK00I": TypeLockCreated, "TLK01I": TypeLockDeleted, "T9006I": TypeLockCreated, "T9007I": TypeLockDeleted,
	"T5000I": TypeAccessRequestCreate, "T5002I": TypeAccessRequestReview, "TC000I": TypeCertCreate,
}

// Event is a normalized Teleport audit event.
type Event struct {
	ID       string          `json:"id"`
	Time     time.Time       `json:"time"`
	Type     string          `json:"type"`
	Code     string          `json:"code"`
	User     string          `json:"user"`
	Resource string          `json:"resource"`
	Success  bool            `json:"success"`
	Summary  string          `json:"summary"`
	Raw      json.RawMessage `json:"raw"`
}

// Page is one page of events, newest first.
type Page struct {
	Items []Event `json:"items"`
	Next  string  `json:"next,omitempty"`
}

// text bounds a Teleport-supplied string and strips control characters.
func text(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	if len(s) > maxText {
		s = s[:maxText]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return strings.TrimSpace(s)
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return text(v)
		}
	}
	return ""
}

// resourceKeys are the fields naming what an event is about, by preference.
var resourceKeys = []string{"server_hostname", "app_name", "db_service", "kubernetes_cluster", "desktop_name", "name", "server_id"}

// failed reports a failure: an explicit success=false, or a Teleport
// warning/error code (…W, …E).
func failed(m map[string]any, code string) bool {
	if s, ok := m["success"].(bool); ok && !s {
		return true
	}
	return strings.HasSuffix(code, "W") || strings.HasSuffix(code, "E")
}

// Normalize maps a Teleport event to the module's bounded shape.
func Normalize(e teleportapi.AuditEvent) Event {
	var m map[string]any
	_ = json.Unmarshal(e.Raw, &m)
	code := text(e.Code)
	typ := text(e.Type)
	if typ == "" {
		typ = codes[code]
	}
	ok := !failed(m, code)
	if typ == TypeLogin && !ok {
		typ = TypeLoginFailure
	}
	out := Event{ID: text(e.ID), Time: e.Time.UTC(), Type: typ, Code: code, User: str(m, "user"), Success: ok, Raw: boundRaw(e.Raw, m)}
	if typ != TypeLogin && typ != TypeLoginFailure {
		out.Resource = str(m, resourceKeys...)
	}
	out.Summary = summary(out)
	return out
}

func summary(e Event) string {
	who := e.User
	if who == "" {
		who = "someone"
	}
	on := func(verb string) string {
		if e.Resource == "" {
			return who + " " + verb
		}
		return who + " " + verb + " on " + e.Resource
	}
	named := func(verb, kind string) string {
		return strings.TrimSpace(who + " " + verb + " " + kind + " " + e.Resource)
	}
	switch e.Type {
	case TypeLogin:
		return who + " signed in"
	case TypeLoginFailure:
		return who + " failed to sign in"
	case TypeSessionStart:
		return on("started a session")
	case TypeSessionEnd:
		return on("ended a session")
	case TypeSessionJoin:
		return on("joined a session")
	case TypeSessionLeave:
		return on("left a session")
	case TypeExec:
		return on("ran a command")
	case TypeAppSessionStart:
		return on("started an application session")
	case TypeDBSessionStart:
		return on("started a database session")
	case TypeDesktopSessionStart:
		return on("started a desktop session")
	case TypeRoleCreated:
		return named("created", "role")
	case TypeRoleUpdated:
		return named("updated", "role")
	case TypeRoleDeleted:
		return named("deleted", "role")
	case TypeLockCreated:
		return named("created", "lock")
	case TypeLockDeleted:
		return named("removed", "lock")
	case TypeUserCreate:
		return named("created", "user")
	case TypeUserUpdate:
		return named("updated", "user")
	case TypeUserDelete:
		return named("deleted", "user")
	case TypePasswordChange:
		return who + " changed their password"
	case TypeResetTokenCreate:
		return named("issued a reset link for", "user")
	case TypeAccessRequestCreate:
		return who + " requested access"
	case TypeAccessRequestReview:
		return who + " reviewed an access request"
	case TypeCertCreate:
		return "certificate issued for " + who
	}
	if e.User == "" {
		return e.Type
	}
	return e.Type + " by " + e.User
}

// boundRaw returns raw (compacted) when it fits in MaxRaw, else the
// top-level scalar fields of m (strings bounded) marked truncated.
func boundRaw(raw json.RawMessage, m map[string]any) json.RawMessage {
	if m == nil { // not a JSON object
		return json.RawMessage(`{}`)
	}
	var buf bytes.Buffer
	if json.Compact(&buf, raw) == nil && buf.Len() <= MaxRaw {
		return buf.Bytes()
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]any{"truncated": true}
	size := len(`{"truncated":true}`)
	for _, k := range keys {
		var v any
		switch x := m[k].(type) {
		case string:
			v = text(x)
		case bool, float64:
			v = x
		default:
			continue
		}
		kb, _ := json.Marshal(text(k))
		vb, _ := json.Marshal(v)
		if size+len(kb)+len(vb)+2 > MaxRaw {
			break
		}
		size += len(kb) + len(vb) + 2
		out[text(k)] = v
	}
	b, _ := json.Marshal(out)
	return b
}

// Query is one event search.
type Query struct {
	From, To time.Time
	Types    []string
	User     string
	Resource string
	Limit    int
	Next     string
}

// SessionQuery is one recorded-session search.
type SessionQuery struct {
	From, To time.Time
	Limit    int
	Next     string
}

func invalid(field, msg string) error { return &clusters.FieldError{Field: field, Msg: msg} }

func window(from, to time.Time, limit int) error {
	switch {
	case from.IsZero():
		return invalid("from", "is required")
	case to.IsZero():
		return invalid("to", "is required")
	case to.Before(from):
		return invalid("to", "must not be before from")
	case to.Sub(from) > MaxWindow:
		return invalid("to", "the window is at most 31 days")
	case limit < 0 || limit > MaxLimit:
		return invalid("limit", "must be 1 to 200")
	}
	return nil
}

func (q Query) validate() error {
	if err := window(q.From, q.To, q.Limit); err != nil {
		return err
	}
	if len(q.Types) > MaxTypes {
		return invalid("types", "at most 32 event types")
	}
	for _, t := range q.Types {
		if !Allowed(t) {
			return invalid("types", "unknown event type")
		}
	}
	if len(q.User) > maxFilter {
		return invalid("user", "must be at most 128 characters")
	}
	if len(q.Resource) > maxFilter {
		return invalid("resource", "must be at most 128 characters")
	}
	return nil
}

func limitOr(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	return n
}

// Service searches a cluster's audit log and the module audit trail.
type Service struct {
	Clusters *clusters.Service
}

// Events searches a cluster's audit events, newest first (audit:read).
func (s *Service) Events(ctx context.Context, clusterID string, q Query) (Page, error) {
	if err := q.validate(); err != nil {
		return Page{}, err
	}
	_, cl, err := s.Clusters.Client(ctx, clusterID, authz.AuditRead)
	if err != nil {
		return Page{}, err
	}
	wanted := q.Types
	if len(wanted) == 0 {
		wanted = EventTypes
	}
	user, res := strings.ToLower(q.User), strings.ToLower(q.Resource)
	match := func(e Event) bool {
		return slices.Contains(wanted, e.Type) &&
			(user == "" || strings.ToLower(e.User) == user) &&
			(res == "" || strings.Contains(strings.ToLower(e.Resource), res))
	}
	limit := limitOr(q.Limit)
	out := Page{Items: []Event{}, Next: q.Next}
	tq := teleportapi.EventQuery{From: q.From.UTC(), To: q.To.UTC(), Types: TeleportTypes(q.Types)}
	for range maxReads {
		tq.Limit, tq.Next = limit-len(out.Items), out.Next
		p, err := cl.SearchEvents(ctx, tq)
		if err != nil {
			return Page{}, err
		}
		dropped := false
		for _, e := range p.Items {
			if n := Normalize(e); match(n) {
				out.Items = append(out.Items, n)
			} else {
				dropped = true
			}
		}
		out.Next = p.Next
		if !dropped || out.Next == "" || len(out.Items) >= limit {
			break
		}
	}
	return out, nil
}

// Session is a recorded session.
type Session struct {
	SID          string    `json:"sid"`
	Participants []string  `json:"participants"`
	User         string    `json:"user"`
	Target       string    `json:"target"`
	Kind         string    `json:"kind"`
	StartedAt    time.Time `json:"started_at"`
	DurationS    int64     `json:"duration_s"`
	PlaybackURL  string    `json:"playback_url,omitempty"`
}

// SessionPage is one page of sessions, newest first.
type SessionPage struct {
	Items []Session `json:"items"`
	Next  string    `json:"next,omitempty"`
}

// Session kinds.
const (
	KindSSH     = "ssh"
	KindKube    = "kube"
	KindDB      = "db"
	KindApp     = "app"
	KindDesktop = "desktop"
)

func timeOf(m map[string]any, key string, def time.Time) time.Time {
	if s, ok := m[key].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC()
		}
	}
	return def
}

// sessionOf maps a session-end event to a Session.
func sessionOf(c clustersView, e teleportapi.AuditEvent) Session {
	var m map[string]any
	_ = json.Unmarshal(e.Raw, &m)
	s := Session{SID: str(m, "sid"), User: str(m, "user"), Participants: []string{}}
	switch {
	case strings.HasPrefix(e.Type, "db."):
		s.Kind, s.Target = KindDB, str(m, "db_service", "db_name")
	case strings.HasPrefix(e.Type, "app."):
		s.Kind, s.Target = KindApp, str(m, "app_name")
	case strings.HasPrefix(e.Type, "windows.desktop."):
		s.Kind, s.Target = KindDesktop, str(m, "desktop_name", "desktop_addr")
	case str(m, "kubernetes_cluster") != "":
		s.Kind, s.Target = KindKube, str(m, "kubernetes_cluster")
	default:
		s.Kind, s.Target = KindSSH, str(m, "server_hostname", "server_id")
	}
	if ps, ok := m["participants"].([]any); ok {
		for _, p := range ps {
			if v, ok := p.(string); ok && text(v) != "" && len(s.Participants) < maxPeople {
				s.Participants = append(s.Participants, text(v))
			}
		}
	}
	if len(s.Participants) == 0 && s.User != "" {
		s.Participants = append(s.Participants, s.User)
	}
	stop := timeOf(m, "session_stop", e.Time.UTC())
	s.StartedAt = timeOf(m, "session_start", stop)
	if d := stop.Sub(s.StartedAt); d > 0 {
		s.DurationS = int64(d / time.Second)
	}
	s.PlaybackURL = PlaybackURL(c.proxy, c.name, s.SID)
	return s
}

type clustersView struct{ proxy, name string }

// Sessions searches a cluster's recorded sessions, newest first (audit:read).
func (s *Service) Sessions(ctx context.Context, clusterID string, q SessionQuery) (SessionPage, error) {
	if err := window(q.From, q.To, q.Limit); err != nil {
		return SessionPage{}, err
	}
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.AuditRead)
	if err != nil {
		return SessionPage{}, err
	}
	p, err := cl.SearchSessions(ctx, teleportapi.EventQuery{From: q.From.UTC(), To: q.To.UTC(), Limit: limitOr(q.Limit), Next: q.Next})
	if err != nil {
		return SessionPage{}, err
	}
	v := clustersView{proxy: c.ProxyAddr, name: c.ClusterName}
	out := SessionPage{Items: make([]Session, 0, len(p.Items)), Next: p.Next}
	for _, e := range p.Items {
		out.Items = append(out.Items, sessionOf(v, e))
	}
	return out, nil
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// PlaybackURL is the Teleport web UI link that plays session sid back
// (research D8): https://<proxy>/web/cluster/<cluster>/session/<sid>, with
// the default port 443 left out. An unusable address, cluster name or
// session id gives "".
func PlaybackURL(proxyAddr, clusterName, sid string) string {
	host, port, err := net.SplitHostPort(proxyAddr)
	if err != nil || host == "" || clusterName == "" || !safeID.MatchString(sid) {
		return ""
	}
	hostport := host
	if port != "443" {
		hostport = net.JoinHostPort(host, port)
	}
	u := url.URL{Scheme: "https", Host: hostport, Path: "/web/cluster/" + clusterName + "/session/" + sid}
	return u.String()
}
