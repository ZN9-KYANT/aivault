package server

// Per-proxy-key rate limiting and spend tracking (SPEC 8.8). Both are
// in-memory and server-local: the RPM window resets on restart, and the
// daily spend counter lives for the current UTC day of the server process.
import (
	"sync"
	"time"
)

// limiter tracks a rolling request window and daily spend per proxy key.
type limiter struct {
	mu    sync.Mutex
	reqs  map[string][]time.Time
	spend map[string]spendDay
}

type spendDay struct {
	day string // UTC date
	usd float64
}

func newLimiter() *limiter {
	return &limiter{reqs: map[string][]time.Time{}, spend: map[string]spendDay{}}
}

// allow admits one request under the per-minute limit (rpm <= 0 = unlimited).
// It returns the retry-after duration when rejected.
func (l *limiter) allow(id string, rpm int, now time.Time) (bool, time.Duration) {
	if rpm <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	windowStart := now.Add(-time.Minute)
	kept := l.reqs[id][:0]
	for _, t := range l.reqs[id] {
		if t.After(windowStart) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rpm {
		l.reqs[id] = kept
		return false, time.Minute - now.Sub(kept[0])
	}
	l.reqs[id] = append(kept, now)
	return true, 0
}

// spendFor returns the tracked USD spend for the current UTC day.
func (l *limiter) spendFor(id string, now time.Time) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	sd, ok := l.spend[id]
	if !ok || sd.day != now.UTC().Format("2006-01-02") {
		return 0
	}
	return sd.usd
}

// addSpend accumulates estimated cost; returns the new daily total.
func (l *limiter) addSpend(id string, usd float64, now time.Time) float64 {
	day := now.UTC().Format("2006-01-02")
	l.mu.Lock()
	defer l.mu.Unlock()
	sd := l.spend[id]
	if sd.day != day {
		sd = spendDay{day: day}
	}
		sd.usd += usd
	l.spend[id] = sd
	return sd.usd
}