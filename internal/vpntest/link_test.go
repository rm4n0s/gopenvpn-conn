// SPDX-License-Identifier: GPL-2.0-only

package vpntest

import (
	"fmt"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

func TestDatagramPairKeepsBoundariesAndOrder(t *testing.T) {
	a, b := NewDatagramPair(LinkOptions{})
	defer func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, msg := range []string{"one", "", "three"} {
		if _, err := a.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 100)
	for _, want := range []string{"one", "", "three"} {
		n, err := b.Read(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("Read = %q, %v; want %q", buf[:n], err, want)
		}
	}
	// A buffer that is too small gets the start, and the rest is dropped.
	if _, err := b.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	small := make([]byte, 3)
	if n, err := a.Read(small); err != nil || string(small[:n]) != "abc" {
		t.Fatalf("Read = %q, %v; want abc", small[:n], err)
	}
	if a.LocalAddr().String() != "a" || a.RemoteAddr().String() != "b" || a.LocalAddr().Network() != "vpntest" {
		t.Errorf("addresses: %v %v", a.LocalAddr(), a.RemoteAddr())
	}
}

// writerFunc is an io.Writer made of a function.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// count writes n datagrams and reads what arrives, for the time it takes.
func count(t *testing.T, opts LinkOptions, n int) (received int, order []int) {
	t.Helper()
	a, b := NewDatagramPair(opts)
	for i := 0; i < n; i++ {
		if _, err := fmt.Fprint(writerFunc(a.Write), i); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(time.Minute)
	synctest.Wait()
	if err := b.SetReadDeadline(time.Now().Add(time.Second)); err != nil { // what is queued is read at once; the end is the deadline
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	for {
		m, err := b.Read(buf)
		if err != nil {
			break
		}
		var v int
		if _, err := fmt.Sscan(string(buf[:m]), &v); err != nil {
			t.Fatal(err)
		}
		order = append(order, v)
		received++
	}
	return received, order
}

func TestDatagramPairFaults(t *testing.T) {
	t.Run("loss", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			got, _ := count(t, LinkOptions{Seed: 1, Loss: 0.5}, 400)
			if got < 140 || got > 260 {
				t.Errorf("%d of 400 arrived with 50%% loss", got)
			}
			if all, _ := count(t, LinkOptions{Seed: 1, Loss: 1}, 50); all != 0 {
				t.Errorf("%d arrived with total loss", all)
			}
		})
	})
	t.Run("duplicates", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			got, _ := count(t, LinkOptions{Seed: 2, Duplicate: 1}, 100)
			if got != 200 {
				t.Errorf("%d arrived, want 200", got)
			}
		})
	})
	t.Run("delays reorder", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			got, order := count(t, LinkOptions{Seed: 3, MaxDelay: 5 * time.Second}, 100)
			if got != 100 {
				t.Fatalf("%d arrived, want 100", got)
			}
			sorted := true
			for i := 1; i < len(order); i++ {
				if order[i] < order[i-1] {
					sorted = false
				}
			}
			if sorted {
				t.Error("nothing was reordered")
			}
		})
	})
	t.Run("the same seed, the same faults", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			opts := LinkOptions{Seed: 9, Loss: 0.3, Duplicate: 0.3, MaxDelay: time.Second}
			_, first := count(t, opts, 100)
			_, second := count(t, opts, 100)
			if fmt.Sprint(first) != fmt.Sprint(second) {
				t.Error("two runs with one seed differ")
			}
		})
	})
}

func TestDatagramPairDeadlinesAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := NewDatagramPair(LinkOptions{})
		buf := make([]byte, 10)

		if err := a.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := a.Read(buf); err != os.ErrDeadlineExceeded {
			t.Fatalf("Read = %v, want os.ErrDeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed != 3*time.Second {
			t.Errorf("Read returned after %v", elapsed)
		}
		// A deadline in the past makes a call that waits return.
		if err := a.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { _, err := a.Read(buf); result <- err }()
		synctest.Wait()
		if err := a.SetDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != os.ErrDeadlineExceeded {
			t.Fatalf("Read = %v, want os.ErrDeadlineExceeded", err)
		}
		if _, err := a.Write([]byte("x")); err != os.ErrDeadlineExceeded {
			t.Errorf("Write after the deadline = %v", err)
		}
		if err := a.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Write([]byte("x")); err != nil {
			t.Errorf("Write after the deadline was lifted = %v", err)
		}

		// Close releases a waiting Read and fails every call after it.
		go func() {
			// The datagram that was sent to b before is read first; the next Read waits.
			if _, err := b.Read(make([]byte, 1)); err != nil {
				result <- err
				return
			}
			_, err := b.Read(buf)
			result <- err
		}()
		synctest.Wait()
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != net.ErrClosed {
			t.Errorf("Read = %v, want net.ErrClosed", err)
		}
		if _, err := b.Write([]byte("x")); err != net.ErrClosed {
			t.Errorf("Write after Close = %v", err)
		}
		if err := b.Close(); err != nil {
			t.Errorf("a second Close = %v", err)
		}
		// Writing to a closed end loses the datagram, as UDP does.
		if _, err := a.Write([]byte("x")); err != nil {
			t.Errorf("Write to a closed peer = %v", err)
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
	})
}
