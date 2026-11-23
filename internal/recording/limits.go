package recording

import "sync"

// Default concurrency bounds (research R8): page reads in flight per module
// instance and per user.
const (
	DefaultConcurrent = 8
	DefaultPerUser    = 2
)

// Limiter bounds concurrent page reads per process and per user.
type Limiter struct {
	mu      sync.Mutex
	total   int
	perUser int
	active  int
	users   map[string]int
}

// NewLimiter bounds total reads and reads per user (<= 0: the defaults; a
// per-user bound above the total is lowered to it).
func NewLimiter(total, perUser int) *Limiter {
	if total <= 0 {
		total = DefaultConcurrent
	}
	if perUser <= 0 {
		perUser = DefaultPerUser
	}
	perUser = min(perUser, total)
	return &Limiter{total: total, perUser: perUser, users: map[string]int{}}
}

// Acquire takes a slot for key (tenant/user); ok is false at either bound.
// release is idempotent.
func (l *Limiter) Acquire(key string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= l.total || l.users[key] >= l.perUser {
		return func() {}, false
	}
	l.active++
	l.users[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.active--
			if l.users[key]--; l.users[key] <= 0 {
				delete(l.users, key)
			}
		})
	}, true
}

// Active is the number of reads in flight.
func (l *Limiter) Active() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active
}
