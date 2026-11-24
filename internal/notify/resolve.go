package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"slices"
)

// ErrNoAddress reports a recipient user id that is not an active member of
// the tenant or has no e-mail address: nothing is sent to it. It is an
// ErrNotDelivered.
var ErrNoAddress = fmt.Errorf("%w: recipient has no address", ErrNotDelivered)

// Directory maps tangra user ids to their e-mail addresses (auth
// Profiles.Members: the login is the member's sign-in e-mail).
type Directory interface {
	// Addresses returns the address of every id that is an active member of
	// the tenant; the others are absent. An error means auth cannot be asked.
	Addresses(ctx context.Context, tenantID string, userIDs []string) (map[string]string, error)
}

// IsAddress reports whether s is a bare e-mail address (what the
// notification module's e-mail channel accepts as a recipient).
func IsAddress(s string) bool {
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == ""
}

// Resolver is the Notifier that turns recipient user ids into e-mail
// addresses before sending through Next: the notification module validates
// To for the channel and does not resolve tangra users. A recipient that is
// already an address is passed through; one without an address is skipped
// (logged by user id, never by address); a directory that cannot be asked is
// ErrUnavailable and nothing is sent.
type Resolver struct {
	next Notifier
	dir  Directory
	log  *slog.Logger
}

// NewResolver wraps next; a nil dir makes every user id ErrUnavailable.
func NewResolver(next Notifier, dir Directory, log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Resolver{next: next, dir: dir, log: log}
}

// Send implements Notifier for the single recipient m.To.
func (r *Resolver) Send(ctx context.Context, m Message) error {
	to, err := r.resolve(ctx, m, []string{m.To})
	if err != nil {
		return err
	}
	if len(to) == 0 {
		return ErrNoAddress
	}
	m.To = to[0]
	return r.next.Send(ctx, m)
}

// SendEach sends m to every recipient of to (user ids or addresses),
// resolving the user ids in one lookup. Skipped recipients are no failure;
// failed sends are joined.
func (r *Resolver) SendEach(ctx context.Context, m Message, to []string) error {
	addrs, err := r.resolve(ctx, m, to)
	if err != nil {
		return err
	}
	var errs []error
	for _, a := range addrs {
		m.To = a
		if err := r.next.Send(ctx, m); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// resolve maps recipients to addresses, in order, without duplicates.
func (r *Resolver) resolve(ctx context.Context, m Message, to []string) ([]string, error) {
	if !slices.Contains(Templates, m.Template) {
		return nil, ErrTemplate
	}
	var ids []string
	for _, t := range to {
		if !IsAddress(t) && !slices.Contains(ids, t) {
			ids = append(ids, t)
		}
	}
	attrs := []any{"template", m.Template, "tenant", m.TenantID, "correlation_id", m.CorrelationID}
	found := map[string]string{}
	if len(ids) > 0 {
		if r.dir == nil {
			r.log.WarnContext(ctx, "notification not sent: no recipient directory", attrs...)
			return nil, ErrUnavailable
		}
		got, err := r.dir.Addresses(ctx, m.TenantID, ids)
		if err != nil {
			r.log.WarnContext(ctx, "notification not sent: recipient directory unavailable", attrs...)
			return nil, ErrUnavailable
		}
		found = got
	}
	var out []string
	seen := map[string]bool{}
	for _, t := range to {
		a := t
		if !IsAddress(t) {
			a = found[t]
			if !IsAddress(a) {
				if !seen["id:"+t] {
					seen["id:"+t] = true
					r.log.WarnContext(ctx, "notification recipient skipped: not an active member with an e-mail address",
						append(attrs, "user_id", t)...)
				}
				continue
			}
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

// SendEach sends m to every recipient of to through n: in one lookup when n
// is a Resolver, one Send per recipient otherwise (failures joined).
func SendEach(ctx context.Context, n Notifier, m Message, to []string) error {
	switch v := n.(type) {
	case nil:
		return ErrUnavailable
	case *Resolver:
		return v.SendEach(ctx, m, to)
	}
	var errs []error
	for _, t := range to {
		m.To = t
		if err := n.Send(ctx, m); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

var _ Notifier = (*Resolver)(nil)
