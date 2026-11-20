package deploy

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

// ErrRateLimited refuses a check run within 10 s of the draft's last one.
var ErrRateLimited = errors.New("deploy: checks were run less than 10 seconds ago")

// Service manages the tenant's deployment drafts (deployments:manage, human
// administrators only). Repo, Authz and Prober are required; a nil Limiter
// is created on first use.
type Service struct {
	Repo    repo.Store
	Authz   *authz.Authorizer
	Prober  *Prober
	Limiter *Limiter
	Audit   audit.Recorder
	Now     func() time.Time

	once sync.Once
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) limiter() *Limiter {
	s.once.Do(func() {
		if s.Limiter == nil {
			s.Limiter = &Limiter{Now: s.Now}
		}
	})
	return s.Limiter
}

// DraftInput is the POST and PUT body. RegisteredClusterID records the
// handover to registration (PUT only; a cluster of the caller's tenant).
type DraftInput struct {
	Domain              string   `json:"domain"`
	CertMode            string   `json:"cert_mode"`
	ACMEEmail           string   `json:"acme_email,omitempty"`
	TeleportVersion     string   `json:"teleport_version"`
	AdminUsername       string   `json:"admin_username"`
	AdminLogins         []string `json:"admin_logins"`
	RegisteredClusterID string   `json:"registered_cluster_id,omitempty"`
}

// DraftView is a draft as the API returns it. ProxyAddr is the address the
// registration dialog is filled with.
type DraftView struct {
	ID                  string            `json:"id"`
	Domain              string            `json:"domain"`
	CertMode            string            `json:"cert_mode"`
	ACMEEmail           string            `json:"acme_email,omitempty"`
	TeleportVersion     string            `json:"teleport_version"`
	AdminUsername       string            `json:"admin_username"`
	AdminLogins         []string          `json:"admin_logins"`
	Checks              []repo.DraftCheck `json:"checks"`
	RegisteredClusterID string            `json:"registered_cluster_id,omitempty"`
	ProxyAddr           string            `json:"proxy_addr"`
	Artifacts           []string          `json:"artifacts"`
	CreatedBy           string            `json:"created_by"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

// DraftPage lists the tenant's drafts, newest first.
type DraftPage struct {
	Items []DraftView `json:"items"`
}

func viewOf(d repo.DeploymentDraft) DraftView {
	v := DraftView{ID: d.ID, Domain: d.Domain, CertMode: d.CertMode, ACMEEmail: d.ACMEEmail, TeleportVersion: d.TeleportVersion,
		AdminUsername: d.AdminUsername, AdminLogins: slices.Clone(d.AdminLogins), Checks: slices.Clone(d.Checks),
		RegisteredClusterID: d.RegisteredClusterID, ProxyAddr: d.Domain + ":443", Artifacts: slices.Clone(Artifacts),
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt.UTC(), UpdatedAt: d.UpdatedAt.UTC()}
	if v.AdminLogins == nil {
		v.AdminLogins = []string{}
	}
	if v.Checks == nil {
		v.Checks = []repo.DraftCheck{}
	}
	return v
}

func inputOf(d repo.DeploymentDraft) Input {
	return Input{Domain: d.Domain, CertMode: d.CertMode, ACMEEmail: d.ACMEEmail, TeleportVersion: d.TeleportVersion,
		AdminUsername: d.AdminUsername, AdminLogins: d.AdminLogins}
}

func (s *Service) record(ctx context.Context, a audit.Action, id string, err error, details map[string]any) {
	clusters.Audit(ctx, s.Audit, a, audit.TargetDeployment, "", id, err, details)
}

// caller checks deployments:manage and returns the caller.
func (s *Service) caller(ctx context.Context) (authz.Subjects, error) {
	if err := s.Authz.Require(ctx, authz.DeploymentsManage); err != nil {
		return authz.Subjects{}, err
	}
	subj, _ := authz.FromContext(ctx)
	return subj, nil
}

func (s *Service) get(ctx context.Context, id string) (repo.DeploymentDraft, error) {
	subj, err := s.caller(ctx)
	if err != nil {
		return repo.DeploymentDraft{}, err
	}
	return s.Repo.GetDraft(ctx, subj.TenantID, id)
}

// List returns the tenant's drafts.
func (s *Service) List(ctx context.Context) (DraftPage, error) {
	subj, err := s.caller(ctx)
	if err != nil {
		return DraftPage{}, err
	}
	ds, err := s.Repo.ListDrafts(ctx, subj.TenantID)
	if err != nil {
		return DraftPage{}, err
	}
	out := DraftPage{Items: make([]DraftView, 0, len(ds))}
	for _, d := range ds {
		out.Items = append(out.Items, viewOf(d))
	}
	return out, nil
}

// Get returns one draft.
func (s *Service) Get(ctx context.Context, id string) (DraftView, error) {
	d, err := s.get(ctx, id)
	if err != nil {
		return DraftView{}, err
	}
	return viewOf(d), nil
}

func apply(d *repo.DeploymentDraft, in DraftInput) error {
	v, err := Validate(Input{Domain: in.Domain, CertMode: in.CertMode, ACMEEmail: in.ACMEEmail, TeleportVersion: in.TeleportVersion,
		AdminUsername: in.AdminUsername, AdminLogins: in.AdminLogins})
	if err != nil {
		return err
	}
	if d.Domain != v.Domain {
		d.Checks = nil // the checks were for another domain
	}
	d.Domain, d.CertMode, d.ACMEEmail, d.TeleportVersion = v.Domain, v.CertMode, v.ACMEEmail, v.TeleportVersion
	d.AdminUsername, d.AdminLogins = v.AdminUsername, v.AdminLogins
	return nil
}

// Create stores a validated draft.
func (s *Service) Create(ctx context.Context, in DraftInput) (v DraftView, err error) {
	subj, err := s.caller(ctx)
	if err != nil {
		return DraftView{}, err
	}
	defer func() { s.record(ctx, audit.DeploymentCreate, v.ID, err, map[string]any{"domain": v.Domain}) }()
	if in.RegisteredClusterID != "" {
		return DraftView{}, &clusters.FieldError{Field: "registered_cluster_id", Msg: "is set once the cluster is registered (update the draft)"}
	}
	now := s.now()
	d := repo.DeploymentDraft{ID: store.NewID(), TenantID: subj.TenantID, CreatedBy: subj.ActorID(), CreatedAt: now, UpdatedAt: now}
	if err := apply(&d, in); err != nil {
		return DraftView{}, err
	}
	if err := s.Repo.CreateDraft(ctx, d); err != nil {
		return DraftView{}, err
	}
	return viewOf(d), nil
}

// Update replaces a draft's inputs; changing the domain clears the checks.
func (s *Service) Update(ctx context.Context, id string, in DraftInput) (v DraftView, err error) {
	d, err := s.get(ctx, id)
	if err != nil {
		return DraftView{}, err
	}
	defer func() { s.record(ctx, audit.DeploymentUpdate, id, err, map[string]any{"domain": d.Domain}) }()
	if err := apply(&d, in); err != nil {
		return DraftView{}, err
	}
	if in.RegisteredClusterID != "" {
		if _, err := s.Repo.GetCluster(ctx, d.TenantID, in.RegisteredClusterID); err != nil {
			return DraftView{}, &clusters.FieldError{Field: "registered_cluster_id", Msg: "must be a cluster registered in this tenant"}
		}
	}
	d.RegisteredClusterID = in.RegisteredClusterID
	updated, err := s.Repo.UpdateDraft(ctx, d)
	if err != nil {
		return DraftView{}, err
	}
	return viewOf(updated), nil
}

// Delete removes a draft.
func (s *Service) Delete(ctx context.Context, id string) (err error) {
	d, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	defer func() { s.record(ctx, audit.DeploymentDelete, id, err, nil) }()
	return s.Repo.DeleteDraft(ctx, d.TenantID, d.ID)
}

// Artifact renders one artifact of a draft (never stored).
func (s *Service) Artifact(ctx context.Context, id, name string) (b []byte, err error) {
	d, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(Artifacts, name) {
		return nil, ErrUnknownArtifact
	}
	defer func() { s.record(ctx, audit.DeploymentArtifact, id, err, map[string]any{"artifact": name}) }()
	return Render(name, inputOf(d))
}

// Check runs the prerequisite checks of a draft through netguard and stores
// the results; at most one run per draft every 10 s (ErrRateLimited).
func (s *Service) Check(ctx context.Context, id string) (v DraftView, err error) {
	d, err := s.get(ctx, id)
	if err != nil {
		return DraftView{}, err
	}
	defer func() {
		ok := 0
		for _, c := range v.Checks {
			if c.OK {
				ok++
			}
		}
		s.record(ctx, audit.DeploymentCheck, id, err, map[string]any{"domain": d.Domain, "passed": ok})
	}()
	if !s.limiter().Allow(d.ID) {
		return DraftView{}, ErrRateLimited
	}
	d.Checks = s.Prober.Run(ctx, d.Domain)
	updated, err := s.Repo.UpdateDraft(ctx, d)
	if err != nil {
		return DraftView{}, err
	}
	return viewOf(updated), nil
}
