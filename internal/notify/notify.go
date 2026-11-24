// Package notify sends the Teleport module's notifications through the
// notification module by system template key (contracts/events-and-tasks.md:
// teleport.alert, teleport.cluster_unreachable, teleport.credential_expiring,
// teleport.invite) over the mTLS mesh. Adapted from warden internal/share.
//
// The connection is obtained on the first send, so the module starts (and
// keeps managing clusters) while notification is down; a failed dial is
// retried on the next send and answers ErrUnavailable (dependency_unavailable,
// FR-034). Template variables may carry one-time values (the invite URL of
// teleport.invite): they are passed to the notification module, whose log
// redaction applies, and are never logged or put into errors here.
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-notification/sdk/v4/pkg/notifyclient"
)

// Template keys (contracts/events-and-tasks.md, Notifications).
const (
	TemplateAlert              = "teleport.alert"
	TemplateClusterUnreachable = "teleport.cluster_unreachable"
	TemplateCredentialExpiring = "teleport.credential_expiring" // #nosec G101 -- a name, not a credential
	TemplateInvite             = "teleport.invite"
)

// Templates lists every template key the module sends.
var Templates = []string{TemplateAlert, TemplateClusterUnreachable, TemplateCredentialExpiring, TemplateInvite}

// Errors (never carry variables).
var (
	ErrUnavailable  = errors.New("notify: notification unavailable")
	ErrNotDelivered = errors.New("notify: notification not delivered")
	ErrTemplate     = errors.New("notify: unknown template")
)

// Message is one notification to one recipient.
type Message struct {
	TenantID      string
	Template      string // one of Templates
	To            string // recipient: an e-mail address, or a tangra user id a Resolver turns into one
	Vars          map[string]string
	CorrelationID string
}

// Notifier sends notifications (Client, or Fake in tests).
type Notifier interface {
	Send(ctx context.Context, m Message) error
}

// Dial obtains the connection to the notification module (Freya.Client).
type Dial func(ctx context.Context) (grpc.ClientConnInterface, error)

// Client is the Notifier over the notification module.
type Client struct {
	dial   Dial
	log    *slog.Logger
	mu     sync.Mutex
	client *notifyclient.Client
}

// NewClient wires the sender; nothing is dialled yet.
func NewClient(dial Dial, log *slog.Logger) *Client {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Client{dial: dial, log: log}
}

func (n *Client) conn(ctx context.Context) (*notifyclient.Client, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.client == nil {
		conn, err := n.dial(ctx)
		if err != nil {
			return nil, err
		}
		n.client = notifyclient.New(conn)
	}
	return n.client, nil
}

// Send implements Notifier. Only a confirmed delivery is success; a
// retryable outcome is ErrNotDelivered too (the caller decides whether to
// try again on its next run).
func (n *Client) Send(ctx context.Context, m Message) error {
	if !slices.Contains(Templates, m.Template) {
		return ErrTemplate
	}
	attrs := []any{"template", m.Template, "tenant", m.TenantID, "correlation_id", m.CorrelationID}
	c, err := n.conn(ctx)
	if err != nil {
		n.log.Warn("notification not sent: notification unreachable", attrs...)
		return ErrUnavailable
	}
	res, err := c.SendKey(ctx, m.TenantID, m.Template, m.To, m.Vars, m.CorrelationID)
	if err != nil {
		st := status.Convert(err)
		n.log.Warn("notification refused", append(attrs, "code", st.Code().String())...)
		return fmt.Errorf("%w (%s)", ErrNotDelivered, st.Code())
	}
	if !res.Sent {
		n.log.Warn("notification not sent", append(attrs, "log_id", res.LogID, "retryable", res.Retryable)...)
		return ErrNotDelivered
	}
	n.log.Info("notification sent", append(attrs, "log_id", res.LogID)...)
	return nil
}

// Fake is an in-memory Notifier for tests.
type Fake struct {
	mu   sync.Mutex
	sent []Message
	err  error
}

// NewFake builds an empty fake.
func NewFake() *Fake { return &Fake{} }

// Send implements Notifier.
func (f *Fake) Send(_ context.Context, m Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, m)
	return nil
}

// SetErr makes every send fail with err (nil clears).
func (f *Fake) SetErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// Sent returns a copy of the delivered messages.
func (f *Fake) Sent() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sent)
}

// OfTemplate returns the delivered messages of one template.
func (f *Fake) OfTemplate(key string) []Message {
	var out []Message
	for _, m := range f.Sent() {
		if m.Template == key {
			out = append(out, m)
		}
	}
	return out
}

var (
	_ Notifier = (*Client)(nil)
	_ Notifier = (*Fake)(nil)
)
