package teleportapi

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// The Fake's US3/US4 surface: join tokens (Join simulates an agent joining
// with one), watchers driven by Emit and EndWatches, and event search over
// AuditEvents and SessionEvents.

type fakeToken struct {
	roles   []string
	expires time.Time
}

func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func keywordsMatch(r Resource, kws []string) bool {
	for _, kw := range kws {
		kw = strings.ToLower(kw)
		hit := strings.Contains(strings.ToLower(r.Name), kw) || strings.Contains(strings.ToLower(r.Hostname), kw)
		for k, v := range r.Labels {
			hit = hit || strings.Contains(strings.ToLower(k), kw) || strings.Contains(strings.ToLower(v), kw)
		}
		if !hit {
			return false
		}
	}
	return true
}

// CreateJoinToken implements Client.
func (f *Fake) CreateJoinToken(_ context.Context, s JoinTokenSpec) (IssuedToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("CreateJoinToken"); err != nil {
		return IssuedToken{}, err
	}
	if len(s.Roles) == 0 {
		return IssuedToken{}, trace.BadParameter("a join token needs a role")
	}
	for _, r := range s.Roles {
		if !slices.Contains(JoinRoles, r) {
			return IssuedToken{}, trace.BadParameter("unknown system role %q", r)
		}
	}
	name := newTokenName()
	if f.tokens == nil {
		f.tokens = map[string]fakeToken{}
	}
	f.tokens[name] = fakeToken{roles: slices.Clone(s.Roles), expires: s.Expires.UTC()}
	f.issued = append(f.issued, name)
	return IssuedToken{Name: secrets.NewSecret([]byte(name)), Expires: s.Expires.UTC()}, nil
}

// DeleteJoinToken implements Client. The NotFound message quotes the name,
// as Teleport's may: the client must not let it through.
func (f *Fake) DeleteJoinToken(_ context.Context, hash []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DeleteJoinToken"); err != nil {
		return err
	}
	for name := range f.tokens {
		if hashMatches(name, hash) {
			delete(f.tokens, name)
			return nil
		}
	}
	return trace.NotFound("token %x not found", hash)
}

// Join reports whether an agent of role could join with token at now: the
// token exists, is unexpired and carries the role.
func (f *Fake) Join(token, role string, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[token]
	switch {
	case !ok:
		return trace.AccessDenied("token not found")
	case !now.Before(t.expires):
		return trace.AccessDenied("token expired")
	case !slices.Contains(t.roles, role):
		return trace.AccessDenied("token does not allow role")
	}
	return nil
}

// IssuedTokens lists every join-token name the fake handed out.
func (f *Fake) IssuedTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.issued)
}

// TokenCount is the number of join tokens on the fake cluster.
func (f *Fake) TokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tokens)
}

// FakeWatcher is a watch on the Fake, fed by Fake.Emit.
type FakeWatcher struct {
	kinds []string
	ch    chan WatchEvent
	done  chan struct{}
	once  sync.Once
	mu    sync.Mutex
	err   error
}

func (w *FakeWatcher) end(err error) {
	w.once.Do(func() {
		w.mu.Lock()
		w.err = err
		w.mu.Unlock()
		close(w.done)
	})
}

// Events implements Watcher.
func (w *FakeWatcher) Events() <-chan WatchEvent { return w.ch }

// Done implements Watcher.
func (w *FakeWatcher) Done() <-chan struct{} { return w.done }

// Error implements Watcher.
func (w *FakeWatcher) Error() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

// Close implements Watcher.
func (w *FakeWatcher) Close() error {
	w.end(nil)
	return nil
}

// Watch implements Client: the new watch first delivers OpInit.
func (f *Fake) Watch(_ context.Context, kinds []string) (Watcher, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("Watch"); err != nil {
		return nil, err
	}
	w := &FakeWatcher{kinds: slices.Clone(kinds), ch: make(chan WatchEvent, 256), done: make(chan struct{})}
	w.ch <- WatchEvent{Op: OpInit}
	f.watchers = append(f.watchers, w)
	return w, nil
}

// live returns the open watchers. Callers hold mu.
func (f *Fake) live() []*FakeWatcher {
	f.watchers = slices.DeleteFunc(f.watchers, func(w *FakeWatcher) bool {
		select {
		case <-w.done:
			return true
		default:
			return false
		}
	})
	return slices.Clone(f.watchers)
}

// Emit delivers ev to every open watcher following its kind (init events to
// all) and reports how many received it.
func (f *Fake) Emit(ev WatchEvent) int {
	f.mu.Lock()
	ws := f.live()
	f.mu.Unlock()
	n := 0
	for _, w := range ws {
		if ev.Op != OpInit && !slices.Contains(w.kinds, ev.Kind) {
			continue
		}
		select {
		case w.ch <- ev:
			n++
		case <-w.done:
		}
	}
	return n
}

// EndWatches ends every open watch with err (a dropped stream).
func (f *Fake) EndWatches(err error) {
	f.mu.Lock()
	ws := f.live()
	f.watchers = nil
	f.mu.Unlock()
	for _, w := range ws {
		w.end(err)
	}
}

// Watchers is the number of open watches.
func (f *Fake) Watchers() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.live())
}

// search filters events by window and types, orders them and pages by offset.
func search(all []AuditEvent, q EventQuery) (Page[AuditEvent], error) {
	if err := q.check(); err != nil {
		return Page[AuditEvent]{}, err
	}
	var in []AuditEvent
	for _, e := range all {
		if e.Time.Before(q.From) || e.Time.After(q.To) {
			continue
		}
		if len(q.Types) > 0 && !slices.Contains(q.Types, e.Type) {
			continue
		}
		in = append(in, e)
	}
	sort.SliceStable(in, func(i, j int) bool {
		if q.Ascending {
			return in[i].Time.Before(in[j].Time)
		}
		return in[i].Time.After(in[j].Time)
	})
	return page(in, ListOptions{Limit: q.Limit, Next: q.Next})
}

// SearchEvents implements Client.
func (f *Fake) SearchEvents(_ context.Context, q EventQuery) (Page[AuditEvent], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("SearchEvents"); err != nil {
		return Page[AuditEvent]{}, err
	}
	return search(f.AuditEvents, q)
}

// SearchSessions implements Client.
func (f *Fake) SearchSessions(_ context.Context, q EventQuery) (Page[AuditEvent], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("SearchSessions"); err != nil {
		return Page[AuditEvent]{}, err
	}
	return search(f.SessionEvents, q)
}
