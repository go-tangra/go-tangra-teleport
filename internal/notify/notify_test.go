package notify

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	notificationv1 "github.com/go-tangra/go-tangra-notification/sdk/v4/api/proto/notification/v1"
)

var ctx = context.Background()

// conn is a fake notification connection answering Notifier/Send.
type conn struct {
	grpc.ClientConnInterface
	got  []*notificationv1.SendRequest
	resp *notificationv1.SendResponse
	err  error
}

func (c *conn) Invoke(_ context.Context, method string, args, reply any, _ ...grpc.CallOption) error {
	if c.err != nil {
		return c.err
	}
	c.got = append(c.got, args.(*notificationv1.SendRequest))
	proto.Merge(reply.(*notificationv1.SendResponse), c.resp)
	return nil
}

func sent() *notificationv1.SendResponse {
	return &notificationv1.SendResponse{Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_SENT, LogId: "log-1"}
}

func TestTemplatesAreInTheModuleNamespace(t *testing.T) {
	for _, k := range Templates {
		if !strings.HasPrefix(k, "teleport.") {
			t.Errorf("template %q outside the teleport namespace", k)
		}
	}
	if len(Templates) != 4 {
		t.Fatalf("templates %v", Templates)
	}
}

// The client dials lazily, sends by template key and never logs variables.
func TestClientSendsByKeyAndKeepsVarsOutOfLogs(t *testing.T) {
	var buf bytes.Buffer
	c := &conn{resp: sent()}
	dials := 0
	n := NewClient(func(context.Context) (grpc.ClientConnInterface, error) { dials++; return c, nil }, slog.New(slog.NewJSONHandler(&buf, nil)))
	if dials != 0 {
		t.Fatal("dialled before the first send")
	}
	m := Message{TenantID: "t1", Template: TemplateClusterUnreachable, To: "ops@example.com",
		Vars: map[string]string{"cluster": "prod", "invite_url": "https://SECRET-LINK"}, CorrelationID: "c-1"}
	if err := n.Send(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := n.Send(ctx, m); err != nil {
		t.Fatal(err)
	}
	if dials != 1 || len(c.got) != 2 {
		t.Fatalf("dials %d sends %d", dials, len(c.got))
	}
	r := c.got[0]
	if r.GetTemplateKey() != TemplateClusterUnreachable || r.GetTenantId() != "t1" || r.GetRecipient() != "ops@example.com" ||
		r.GetVariables()["cluster"] != "prod" || r.GetCorrelationId() != "c-1" {
		t.Fatalf("request %+v", r)
	}
	// Refusals and retryable outcomes are errors; nothing logs the variables.
	c.resp = &notificationv1.SendResponse{Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_FAILED, Retryable: true}
	if err := n.Send(ctx, m); !errors.Is(err, ErrNotDelivered) {
		t.Fatalf("failed delivery: %v", err)
	}
	c.err = status.Error(codes.InvalidArgument, "unknown key")
	if err := n.Send(ctx, m); !errors.Is(err, ErrNotDelivered) {
		t.Fatalf("refused: %v", err)
	}
	if strings.Contains(buf.String(), "SECRET-LINK") || strings.Contains(buf.String(), "invite_url") {
		t.Fatalf("variables logged: %s", buf.String())
	}
}

// A dial failure is ErrUnavailable and is retried on the next send.
func TestClientUnavailable(t *testing.T) {
	fail := true
	c := &conn{resp: sent()}
	n := NewClient(func(context.Context) (grpc.ClientConnInterface, error) {
		if fail {
			return nil, errors.New("down")
		}
		return c, nil
	}, nil)
	if err := n.Send(ctx, Message{TenantID: "t1", Template: TemplateAlert, To: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dial failure: %v", err)
	}
	fail = false
	if err := n.Send(ctx, Message{TenantID: "t1", Template: TemplateAlert, To: "x"}); err != nil {
		t.Fatal(err)
	}
	// Unknown templates are refused before any call.
	if err := n.Send(ctx, Message{TenantID: "t1", Template: "auth.invite", To: "x"}); !errors.Is(err, ErrTemplate) {
		t.Fatalf("foreign template: %v", err)
	}
}

func TestFake(t *testing.T) {
	f := NewFake()
	if err := f.Send(ctx, Message{TenantID: "t1", Template: TemplateCredentialExpiring, To: "a"}); err != nil {
		t.Fatal(err)
	}
	f.SetErr(ErrUnavailable)
	if err := f.Send(ctx, Message{TenantID: "t1", Template: TemplateCredentialExpiring, To: "b"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if got := f.Sent(); len(got) != 1 || got[0].To != "a" || len(f.OfTemplate(TemplateCredentialExpiring)) != 1 {
		t.Fatalf("sent %+v", got)
	}
	var _ Notifier = f
	var _ Notifier = (*Client)(nil)
}
