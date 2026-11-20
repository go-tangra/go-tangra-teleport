// Package tokens is the join-token part of US3 (FR-016…018, research D9):
// create a short-lived token for one resource type with a ready-to-run
// install command, list the tokens of a cluster without their values, and
// revoke one, which deletes it in Teleport so a later join is refused.
//
// The token name is the secret an agent presents. It exists only as
// secrets.OneTime in the result of Create (with the install command and the
// config snippet that embed it, SR-002): it is never logged, cached,
// published, audited or stored. The module keeps the SHA-256 of the name to
// find the token again for revocation. Operators may create and revoke
// tokens (tokens:manage, SR-005); workers never can (human-only).
package tokens

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// TTL bounds in minutes (FR-016).
const (
	DefaultTTLMinutes = 30
	MinTTLMinutes     = 1
	MaxTTLMinutes     = 24 * 60
)

// Roles maps each resource type to the Teleport system role its token grants.
var Roles = map[string]string{
	repo.KindNode:    teleportapi.RoleNode,
	repo.KindApp:     teleportapi.RoleApp,
	repo.KindDB:      teleportapi.RoleDB,
	repo.KindKube:    teleportapi.RoleKube,
	repo.KindDesktop: teleportapi.RoleDesktop,
}

// Service manages a cluster's join tokens. Clusters and Repo are required;
// the others may be nil.
type Service struct {
	Clusters *clusters.Service
	Repo     repo.JoinTokens
	Audit    audit.Recorder
	Events   events.Publisher
	Now      func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// CreateInput is the POST body (nil TTL: the default).
type CreateInput struct {
	ResourceType string `json:"resource_type"`
	TTLMinutes   *int   `json:"ttl_minutes,omitempty"`
}

// Created is the create result: the token, its install command and its
// config snippet appear here only.
type Created struct {
	ID             string          `json:"id"`
	ResourceType   string          `json:"resource_type"`
	Token          secrets.OneTime `json:"token"`
	ExpiresAt      time.Time       `json:"expires_at"`
	InstallCommand secrets.OneTime `json:"install_command"`
	ConfigSnippet  secrets.OneTime `json:"config_snippet"`
}

// View is a token's metadata (never its value).
type View struct {
	ID           string     `json:"id"`
	ResourceType string     `json:"resource_type"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	Expired      bool       `json:"expired"`
	Revoked      bool       `json:"revoked"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// Page lists a cluster's tokens, newest first.
type Page struct {
	Items []View `json:"items"`
}

func (s *Service) viewOf(t repo.JoinToken, now time.Time) View {
	v := View{ID: t.ID, ResourceType: t.ResourceType, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt.UTC(), ExpiresAt: t.ExpiresAt.UTC(),
		Expired: !now.Before(t.ExpiresAt), Revoked: !t.RevokedAt.IsZero()}
	if v.Revoked {
		at := t.RevokedAt.UTC()
		v.RevokedAt = &at
	}
	return v
}

func (s *Service) record(ctx context.Context, a audit.Action, clusterID, id string, err error, details map[string]any) {
	clusters.Audit(ctx, s.Audit, a, audit.TargetToken, clusterID, id, err, details)
}

// validate checks the input and returns the role and TTL.
func validate(in CreateInput) (string, time.Duration, error) {
	role, ok := Roles[in.ResourceType]
	if !ok {
		return "", 0, &clusters.FieldError{Field: "resource_type", Msg: "must be node, app, db, kube or desktop"}
	}
	minutes := DefaultTTLMinutes
	if in.TTLMinutes != nil {
		minutes = *in.TTLMinutes
	}
	if minutes < MinTTLMinutes || minutes > MaxTTLMinutes {
		return "", 0, &clusters.FieldError{Field: "ttl_minutes", Msg: "must be 1 to 1440"}
	}
	return role, time.Duration(minutes) * time.Minute, nil
}

// Create issues a join token (tokens:manage).
func (s *Service) Create(ctx context.Context, clusterID string, in CreateInput) (out Created, err error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.TokensManage)
	if err != nil {
		return Created{}, err
	}
	id := store.NewID()
	var ttl time.Duration
	defer func() {
		target := id
		if err != nil {
			target = ""
		}
		s.record(ctx, audit.TokenCreate, c.ID, target, err, map[string]any{"resource_type": in.ResourceType, "ttl_minutes": int(ttl.Minutes())})
	}()
	if err := clusters.Writable(c); err != nil {
		return Created{}, err
	}
	role, ttl, err := validate(in)
	if err != nil {
		return Created{}, err
	}
	now := s.now()
	tok, err := cl.CreateJoinToken(ctx, teleportapi.JoinTokenSpec{Roles: []string{role}, Expires: now.Add(ttl)})
	if err != nil {
		return Created{}, err
	}
	inst, err := Render(in.ResourceType, c.ProxyAddr, string(tok.Name.Reveal()))
	if err != nil {
		s.rollback(ctx, cl, tok)
		return Created{}, err
	}
	subj, _ := authz.FromContext(ctx)
	row := repo.JoinToken{ID: id, TenantID: c.TenantID, ClusterID: c.ID, TokenHash: teleportapi.TokenHash(tok.Name),
		ResourceType: in.ResourceType, ExpiresAt: tok.Expires, CreatedBy: subj.ActorID(), CreatedAt: now}
	if err := s.Repo.CreateJoinToken(ctx, row); err != nil {
		// An unrecorded token could never be listed or revoked: drop it.
		s.rollback(ctx, cl, tok)
		return Created{}, err
	}
	events.Emit(ctx, s.Events, c.TenantID, events.TokenCreated, events.Token{ClusterID: c.ID, TokenID: id, ResourceType: in.ResourceType})
	return Created{ID: id, ResourceType: in.ResourceType, Token: secrets.NewOneTime(tok.Name), ExpiresAt: tok.Expires,
		InstallCommand: secrets.NewOneTime(secrets.NewSecret([]byte(inst.Command))),
		ConfigSnippet:  secrets.NewOneTime(secrets.NewSecret([]byte(inst.Config)))}, nil
}

// rollback deletes a token the module could not record (best effort, with
// a fresh deadline so a cancelled request still cleans up).
func (s *Service) rollback(ctx context.Context, cl teleportapi.Client, tok teleportapi.IssuedToken) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = cl.DeleteJoinToken(ctx, teleportapi.TokenHash(tok.Name))
}

// List returns the cluster's token metadata (tokens:manage).
func (s *Service) List(ctx context.Context, clusterID string) (Page, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.TokensManage)
	if err != nil {
		return Page{}, err
	}
	rows, err := s.Repo.ListJoinTokens(ctx, c.TenantID, c.ID)
	if err != nil {
		return Page{}, err
	}
	now := s.now()
	out := Page{Items: make([]View, 0, len(rows))}
	for _, r := range rows {
		out.Items = append(out.Items, s.viewOf(r, now))
	}
	return out, nil
}

// Revoke deletes the token in Teleport and records the revocation
// (tokens:manage). Revoking a revoked token is a no-op; a token Teleport
// already dropped (expired) is revoked locally.
func (s *Service) Revoke(ctx context.Context, clusterID, id string) (err error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.TokensManage)
	if err != nil {
		return err
	}
	kind := ""
	defer func() {
		s.record(ctx, audit.TokenRevoke, c.ID, id, err, map[string]any{"resource_type": kind})
	}()
	if err := clusters.Writable(c); err != nil {
		return err
	}
	t, err := s.Repo.GetJoinToken(ctx, c.TenantID, id)
	if err != nil {
		return err
	}
	if t.ClusterID != c.ID {
		return repo.ErrNotFound
	}
	kind = t.ResourceType
	if !t.RevokedAt.IsZero() {
		return nil
	}
	if err := cl.DeleteJoinToken(ctx, t.TokenHash); err != nil && !errors.Is(err, teleportapi.ErrNotFound) {
		return err
	}
	if err := s.Repo.RevokeJoinToken(ctx, c.TenantID, id, s.now()); err != nil {
		return err
	}
	events.Emit(ctx, s.Events, c.TenantID, events.TokenRevoked, events.Token{ClusterID: c.ID, TokenID: id, ResourceType: kind})
	return nil
}
