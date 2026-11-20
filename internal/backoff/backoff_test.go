package backoff

import (
	"testing"
	"time"
)

func TestCeilingDoublesToMax(t *testing.T) {
	b := &Backoff{Rand: func() float64 { return 0.999999 }}
	want := []time.Duration{5, 10, 20, 40, 80, 160, 320, 600, 600, 600}
	for i, w := range want {
		if c := b.Ceiling(); c != w*time.Second {
			t.Fatalf("attempt %d: ceiling %v, want %v", i, c, w*time.Second)
		}
		d := b.Next()
		if d >= w*time.Second || d < w*time.Second*99/100 {
			t.Fatalf("attempt %d: delay %v not just under %v", i, d, w*time.Second)
		}
	}
	if b.Attempts() != len(want) {
		t.Fatalf("attempts %d", b.Attempts())
	}
	b.Reset()
	if b.Ceiling() != 5*time.Second {
		t.Fatal("reset failed")
	}
}

func TestFullJitterRange(t *testing.T) {
	tests := []struct {
		r    float64
		want time.Duration
	}{
		{0, time.Second}, // floor
		{0.5, 2500 * time.Millisecond},
		{0.1, time.Second}, // 0.5 s raised to the floor
	}
	for _, tt := range tests {
		b := &Backoff{Rand: func() float64 { return tt.r }}
		if d := b.Next(); d != tt.want {
			t.Errorf("r=%v: %v, want %v", tt.r, d, tt.want)
		}
	}
	// Real randomness stays in range.
	b := &Backoff{}
	for i := 0; i < 1000; i++ {
		c := b.Ceiling()
		if d := b.Next(); d < time.Second || d > c {
			t.Fatalf("delay %v outside [1s, %v]", d, c)
		}
	}
}

func TestAfterHonoursRetryAfter(t *testing.T) {
	b := &Backoff{Rand: func() float64 { return 0 }}
	if d := b.After(90 * time.Second); d != 90*time.Second {
		t.Fatalf("got %v", d)
	}
	if d := b.After(48 * time.Hour); d != MaxRetryAfter {
		t.Fatalf("not capped: %v", d)
	}
	b = &Backoff{Rand: func() float64 { return 0.9 }, Base: time.Minute}
	if d := b.After(time.Second); d != 54*time.Second {
		t.Fatalf("backoff should win: %v", d)
	}
}
