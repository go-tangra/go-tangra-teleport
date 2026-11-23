package recording

import "testing"

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, 2)
	r1, ok1 := l.Acquire("t/a")
	r2, ok2 := l.Acquire("t/a")
	if !ok1 || !ok2 {
		t.Fatal("two for one user")
	}
	if _, ok := l.Acquire("t/a"); ok {
		t.Fatal("third for one user")
	}
	r3, ok := l.Acquire("t/b")
	if !ok {
		t.Fatal("another user")
	}
	if _, ok := l.Acquire("t/c"); ok {
		t.Fatal("over the process bound")
	}
	r1()
	r1() // idempotent
	if _, ok := l.Acquire("t/c"); !ok {
		t.Fatal("slot not freed")
	}
	if _, ok := l.Acquire("t/a"); ok {
		t.Fatal("process bound after a double release")
	}
	r2()
	r3()
	if n := l.Active(); n != 1 {
		t.Fatalf("active %d", n)
	}
	// Defaults and a per-user bound above the total.
	d := NewLimiter(0, 0)
	if d.total != DefaultConcurrent || d.perUser != DefaultPerUser {
		t.Fatalf("defaults %+v", d)
	}
	if x := NewLimiter(1, 5); x.perUser != 1 {
		t.Fatalf("per user %d", x.perUser)
	}
}
