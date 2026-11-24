package notify

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

// dir is an in-memory Directory: addrs holds the active members with an
// address; calls records every lookup.
type dir struct {
	addrs map[string]string
	err   error
	calls [][]string
}

func (d *dir) Addresses(_ context.Context, _ string, ids []string) (map[string]string, error) {
	d.calls = append(d.calls, slices.Clone(ids))
	if d.err != nil {
		return nil, d.err
	}
	out := map[string]string{}
	for _, id := range ids {
		if a, ok := d.addrs[id]; ok {
			out[id] = a
		}
	}
	return out, nil
}

func resolver(d Directory) (*Resolver, *Fake, *bytes.Buffer) {
	var buf bytes.Buffer
	f := NewFake()
	return NewResolver(f, d, slog.New(slog.NewJSONHandler(&buf, nil))), f, &buf
}

func msg(to string) Message {
	return Message{TenantID: "t1", Template: TemplateInvite, To: to, Vars: map[string]string{"invite_url": "https://secret/invite"}, CorrelationID: "c1"}
}

func TestResolverSendsToTheMembersAddress(t *testing.T) {
	r, f, buf := resolver(&dir{addrs: map[string]string{"u1": "alice@example.com"}})
	if err := r.Send(ctx, msg("u1")); err != nil {
		t.Fatal(err)
	}
	got := f.Sent()
	if len(got) != 1 || got[0].To != "alice@example.com" || got[0].Vars["invite_url"] == "" {
		t.Fatalf("sent %+v", got)
	}
	if strings.Contains(buf.String(), "alice@") || strings.Contains(buf.String(), "secret") {
		t.Fatalf("address or variables logged: %s", buf)
	}
}

func TestResolverPassesAddressesThrough(t *testing.T) {
	d := &dir{}
	r, f, _ := resolver(d)
	if err := r.Send(ctx, msg("bob@example.com")); err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 0 || f.Sent()[0].To != "bob@example.com" {
		t.Fatalf("calls %v sent %+v", d.calls, f.Sent())
	}
}

// A user id that is not an active member (or whose login is no address) is
// skipped: nothing is sent, the send is not delivered, and the log names
// the user id only.
func TestResolverSkipsRecipientsWithoutAddress(t *testing.T) {
	for _, d := range []*dir{{addrs: map[string]string{}}, {addrs: map[string]string{"u1": "not-an-address"}}} {
		r, f, buf := resolver(d)
		err := r.Send(ctx, msg("u1"))
		if !errors.Is(err, ErrNoAddress) || !errors.Is(err, ErrNotDelivered) {
			t.Fatalf("err %v", err)
		}
		if len(f.Sent()) != 0 || !strings.Contains(buf.String(), "u1") || strings.Contains(buf.String(), "not-an-address") {
			t.Fatalf("sent %+v log %s", f.Sent(), buf)
		}
	}
}

func TestResolverAuthDownIsUnavailable(t *testing.T) {
	r, f, _ := resolver(&dir{err: errors.New("auth down")})
	if err := r.Send(ctx, msg("u1")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
	if err := r.SendEach(ctx, msg(""), []string{"u1", "u2"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("each: %v", err)
	}
	if len(f.Sent()) != 0 {
		t.Fatalf("sent %+v", f.Sent())
	}
	if err := NewResolver(f, nil, nil).Send(ctx, msg("u1")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no directory: %v", err)
	}
}

func TestResolverRejectsUnknownTemplatesBeforeAsking(t *testing.T) {
	d := &dir{}
	r, _, _ := resolver(d)
	m := msg("u1")
	m.Template = "x"
	if err := r.Send(ctx, m); !errors.Is(err, ErrTemplate) || len(d.calls) != 0 {
		t.Fatalf("err %v calls %v", err, d.calls)
	}
	if err := r.SendEach(ctx, m, []string{"u1"}); !errors.Is(err, ErrTemplate) {
		t.Fatalf("each: %v", err)
	}
}

// SendEach resolves every user id in one lookup (duplicates once), passes
// addresses through, skips members without an address and sends to the rest.
func TestResolverSendEachBatches(t *testing.T) {
	d := &dir{addrs: map[string]string{"u1": "a@example.com", "u3": "c@example.com"}}
	r, f, _ := resolver(d)
	if err := r.SendEach(ctx, msg(""), []string{"u1", "u2", "u3", "u1", "x@example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 1 || !slices.Equal(d.calls[0], []string{"u1", "u2", "u3"}) {
		t.Fatalf("lookups %v", d.calls)
	}
	var to []string
	for _, m := range f.Sent() {
		to = append(to, m.To)
	}
	if !slices.Equal(to, []string{"a@example.com", "c@example.com", "x@example.com"}) {
		t.Fatalf("sent to %v", to)
	}
	if err := r.SendEach(ctx, msg(""), nil); err != nil || len(d.calls) != 1 {
		t.Fatalf("empty: %v %v", err, d.calls)
	}
}

func TestResolverSendEachJoinsSendFailures(t *testing.T) {
	r, f, _ := resolver(&dir{addrs: map[string]string{"u1": "a@example.com"}})
	f.SetErr(ErrNotDelivered)
	if err := r.SendEach(ctx, msg(""), []string{"u1", "b@example.com"}); !errors.Is(err, ErrNotDelivered) {
		t.Fatalf("err %v", err)
	}
}

// The package helper batches through a Resolver and loops otherwise.
func TestSendEachHelper(t *testing.T) {
	d := &dir{addrs: map[string]string{"u1": "a@example.com", "u2": "b@example.com"}}
	r, f, _ := resolver(d)
	if err := SendEach(ctx, r, msg(""), []string{"u1", "u2"}); err != nil || len(d.calls) != 1 || len(f.Sent()) != 2 {
		t.Fatalf("err %v calls %v sent %d", err, d.calls, len(f.Sent()))
	}
	plain := NewFake()
	if err := SendEach(ctx, plain, msg(""), []string{"u1", "u2"}); err != nil || len(plain.Sent()) != 2 || plain.Sent()[1].To != "u2" {
		t.Fatalf("plain: %v %+v", err, plain.Sent())
	}
	plain.SetErr(ErrUnavailable)
	if err := SendEach(ctx, plain, msg(""), []string{"u1"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("plain err %v", err)
	}
	if err := SendEach(ctx, nil, msg(""), []string{"u1"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil notifier: %v", err)
	}
}

func TestIsAddress(t *testing.T) {
	for s, want := range map[string]bool{"a@example.com": true, "A.B+c@sub.example.org": true, "": false, "u1": false,
		"018f3a2b-0000-7000-8000-100000000000": false, "Alice <a@example.com>": false, "a@": false, "@b": false} {
		if got := IsAddress(s); got != want {
			t.Errorf("IsAddress(%q) = %v", s, got)
		}
	}
}
