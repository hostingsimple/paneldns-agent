package engine

import (
	"context"
	"testing"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/protocol"
)

// TestCheckRequested: a heartbeat answer with check_requested runs the
// service's self-check once, and at most once every CheckRequestInterval
// however often PanelDNS asks (D-35).
func TestCheckRequested(t *testing.T) {
	e, _, api, c := newFixture(t)
	ctx := context.Background()
	calls := 0
	e.CheckRequested = func(context.Context) { calls++ }

	e.RunRequestedCheck(ctx) // nothing asked yet
	if calls != 0 {
		t.Fatalf("ran without a request: %d", calls)
	}
	ask := func() {
		api.hbResp = &protocol.HeartbeatResponse{CheckRequested: true}
		if err := e.heartbeat(ctx, false); err != nil {
			t.Fatal(err)
		}
		e.RunRequestedCheck(ctx)
	}
	ask()
	if calls != 1 {
		t.Fatalf("calls %d, want 1", calls)
	}
	e.RunRequestedCheck(ctx) // the request was used up
	c.add(time.Minute)
	ask() // asked again within the interval
	if calls != 1 {
		t.Fatalf("calls %d within %s, want 1", calls, CheckRequestInterval)
	}
	c.add(CheckRequestInterval)
	ask()
	if calls != 2 {
		t.Fatalf("calls %d after the interval, want 2", calls)
	}

	// Without a callback (an older caller) a request is ignored.
	e.CheckRequested = nil
	c.add(CheckRequestInterval)
	ask()
	if calls != 2 {
		t.Fatalf("calls %d", calls)
	}
}
