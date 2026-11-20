// Package backoff implements exponential backoff with full jitter
// (spec 7.5: 5 s doubling to 10 min).
package backoff

import (
	"math/rand/v2"
	"time"
)

// Defaults from spec 7.5.
const (
	DefaultBase = 5 * time.Second
	DefaultMax  = 10 * time.Minute
	// MaxRetryAfter caps a server's Retry-After so a bad header can't park
	// the agent for days.
	MaxRetryAfter = time.Hour
)

// Backoff tracks consecutive failures. The zero value uses the defaults.
type Backoff struct {
	Base time.Duration
	Max  time.Duration
	// Rand returns a number in [0, 1); nil uses math/rand/v2.
	Rand func() float64

	attempt int
}

// Ceiling returns the upper bound of the next delay: min(Max, Base*2^n).
func (b *Backoff) Ceiling() time.Duration {
	base, max := b.Base, b.Max
	if base <= 0 {
		base = DefaultBase
	}
	if max <= 0 {
		max = DefaultMax
	}
	d := base
	for i := 0; i < b.attempt; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	if d > max {
		return max
	}
	return d
}

// Next returns the delay before the next attempt and counts a failure.
// With full jitter the delay is uniform in [0, Ceiling()), but never
// shorter than one second so a failing server isn't hammered.
func (b *Backoff) Next() time.Duration {
	c := b.Ceiling()
	r := b.Rand
	if r == nil {
		r = rand.Float64
	}
	d := time.Duration(r() * float64(c))
	if d < time.Second {
		d = time.Second
	}
	b.attempt++
	return d
}

// After returns the delay honouring a server Retry-After: the larger of
// the jittered backoff and retryAfter (capped at MaxRetryAfter).
func (b *Backoff) After(retryAfter time.Duration) time.Duration {
	d := b.Next()
	if retryAfter > MaxRetryAfter {
		retryAfter = MaxRetryAfter
	}
	if retryAfter > d {
		return retryAfter
	}
	return d
}

// Reset clears the failure count after a success.
func (b *Backoff) Reset() { b.attempt = 0 }

// Attempts returns the number of consecutive failures.
func (b *Backoff) Attempts() int { return b.attempt }
