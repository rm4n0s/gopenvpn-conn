// SPDX-License-Identifier: GPL-2.0-only

package ovpn

import (
	"context"
	"fmt"
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
)

// attempt is one call of the fake dial function.
type attempt struct {
	network, address string
	config           *openvpn.Config
	timeLeft         time.Duration // the ServerPollTimeout of the attempt's Config
}

// fakeDialer answers the n-th call with results[n], and records the calls. A result
// with a nil conn and a nil err is a server that does not answer: it blocks for the
// ServerPollTimeout of the Config, as openvpn.Dial does, or until the context is done.
type fakeDialer struct {
	results []fakeResult
	calls   []attempt
}

type fakeResult struct {
	conn *openvpn.Conn
	err  error
}

func (d *fakeDialer) dial(ctx context.Context, network, address string, config *openvpn.Config) (*openvpn.Conn, error) {
	a := attempt{network: network, address: address, config: config, timeLeft: config.ServerPollTimeout}
	d.calls = append(d.calls, a)
	r := d.results[len(d.calls)-1]
	if r.conn == nil && r.err == nil {
		timer := time.NewTimer(config.ServerPollTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil, errors.New(tagFakeNoAnswer, "the server did not answer")
		case <-ctx.Done():
			return nil, errors.NewErr(tagFakeNoAnswer, ctx.Err())
		}
	}
	return r.conn, r.err
}

func (d *fakeDialer) addresses() []string {
	var out []string
	for _, c := range d.calls {
		out = append(out, c.address)
	}
	return out
}

func inOrder(n int, random bool) []int { return shuffled(n, false) }

func threeRemotes() []Remote {
	return []Remote{{"udp", "a.example:1194"}, {"tcp", "b.example:443"}, {"udp6", "[2001:db8::1]:1194"}}
}

func TestProfileDialOrder(t *testing.T) {
	conn := &openvpn.Conn{}
	cfg := &openvpn.Config{MTU: 1400}
	rows := []struct {
		name      string
		random    bool
		order     func(n int, random bool) []int
		results   []fakeResult
		wantConn  bool
		wantCalls []string
	}{
		{"profile order, first answers", false, inOrder, []fakeResult{{conn: conn}}, true, []string{"a.example:1194"}},
		{"profile order, second answers", false, inOrder,
			[]fakeResult{{err: errors.New(tagFakeFail, "no")}, {conn: conn}}, true, []string{"a.example:1194", "b.example:443"}},
		{"first dead, second dead, third alive", false, inOrder,
			[]fakeResult{{err: errors.New(tagFakeFail, "no")}, {err: errors.New(tagFakeFail, "no")}, {conn: conn}}, true,
			[]string{"a.example:1194", "b.example:443", "[2001:db8::1]:1194"}},
		{"remote-random with an order that is fixed", true,
			func(n int, random bool) []int {
				if !random || n != 3 {
					t.Errorf("order(%d, %v)", n, random)
				}
				return []int{2, 0, 1}
			},
			[]fakeResult{{err: errors.New(tagFakeFail, "no")}, {conn: conn}}, true,
			[]string{"[2001:db8::1]:1194", "a.example:1194"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			d := &fakeDialer{results: row.results}
			p := &Profile{Config: cfg, Remotes: threeRemotes(), RemoteRandom: row.random, ConnectTimeout: 5 * time.Second}
			got, err := p.dial(t.Context(), row.order, d.dial)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			if got != conn {
				t.Errorf("conn = %p, want %p", got, conn)
			}
			if !slices.Equal(d.addresses(), row.wantCalls) {
				t.Errorf("tried %v, want %v", d.addresses(), row.wantCalls)
			}
			for _, c := range d.calls {
				// A copy of the profile's Config, with the time for the server to answer.
				if c.config.MTU != 1400 || c.config.ServerPollTimeout != 5*time.Second {
					t.Errorf("the attempt at %s got the Config %+v", c.address, c.config)
				}
			}
			if cfg.ServerPollTimeout != 0 {
				t.Errorf("the Config of the profile was changed: ServerPollTimeout = %v", cfg.ServerPollTimeout)
			}
		})
	}
	t.Run("each remote is dialed with its own network", func(t *testing.T) {
		d := &fakeDialer{results: []fakeResult{
			{err: errors.New(tagFakeFail, "no")}, {err: errors.New(tagFakeFail, "no")}, {conn: conn},
		}}
		p := &Profile{Config: cfg, Remotes: threeRemotes(), ConnectTimeout: time.Second}
		if _, err := p.dial(t.Context(), inOrder, d.dial); err != nil {
			t.Fatalf("dial: %v", err)
		}
		var got []string
		for _, c := range d.calls {
			got = append(got, c.network)
		}
		if want := []string{"udp", "tcp", "udp6"}; !slices.Equal(got, want) {
			t.Errorf("networks %v, want %v", got, want)
		}
	})
}

func TestShuffled(t *testing.T) {
	if got := shuffled(5, false); !slices.Equal(got, []int{0, 1, 2, 3, 4}) {
		t.Errorf("shuffled(5, false) = %v", got)
	}
	if got := shuffled(0, true); len(got) != 0 {
		t.Errorf("shuffled(0, true) = %v", got)
	}
	if got := shuffled(1, true); !slices.Equal(got, []int{0}) {
		t.Errorf("shuffled(1, true) = %v", got)
	}
	// A random order is a permutation, and over many runs it is not always the same.
	seen := map[string]bool{}
	for range 200 {
		got := shuffled(4, true)
		sorted := slices.Clone(got)
		slices.Sort(sorted)
		if !slices.Equal(sorted, []int{0, 1, 2, 3}) {
			t.Fatalf("shuffled(4, true) = %v is not a permutation", got)
		}
		seen[fmt.Sprint(got)] = true
	}
	if len(seen) < 12 {
		t.Errorf("200 shuffles of 4 gave %d different orders, want at least 12 of 24", len(seen))
	}
}

func TestProfileDialAllFailed(t *testing.T) {
	d := &fakeDialer{results: []fakeResult{
		{err: errors.New(tagFakeFirst, "first")}, {err: errors.New(tagFakeSecond, "second")}, {err: errors.New(tagFakeThird, "third")},
	}}
	p := &Profile{Config: &openvpn.Config{}, Remotes: threeRemotes(), ConnectTimeout: time.Second}
	conn, err := p.dial(t.Context(), inOrder, d.dial)
	if conn != nil {
		t.Errorf("conn = %v, want nil", conn)
	}
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not an *errors.Error", err, err)
	}
	if appErr.Tag != tagFakeThird {
		t.Errorf("tag = %s, want the one of the last remote", appErr.Tag)
	}
	if appErr.Metadata["remotes_tried"] != 3 || appErr.Metadata["remotes"] != 3 {
		t.Errorf("metadata = %v", appErr.Metadata)
	}
	if len(d.calls) != 3 {
		t.Errorf("%d remotes tried, want 3", len(d.calls))
	}
}

func TestProfileDialUntaggedError(t *testing.T) {
	// An error that is not an *errors.Error comes back as it is.
	d := &fakeDialer{results: []fakeResult{{err: net.ErrClosed}}}
	p := &Profile{Config: &openvpn.Config{}, Remotes: threeRemotes()[:1], ConnectTimeout: time.Second}
	_, err := p.dial(t.Context(), inOrder, d.dial)
	if err != net.ErrClosed {
		t.Errorf("err = %v, want net.ErrClosed", err)
	}
}

func TestProfileDialErrors(t *testing.T) {
	never := func(ctx context.Context, network, address string, config *openvpn.Config) (*openvpn.Conn, error) {
		t.Errorf("a remote was tried: %s", address)
		return nil, nil
	}
	credentials := func(ctx context.Context) (openvpn.Credentials, error) {
		return openvpn.Credentials{Username: "u", Password: "p"}, nil
	}
	rows := []struct {
		name    string
		profile *Profile
		tag     string
		route   string
	}{
		{"no remotes", &Profile{Config: &openvpn.Config{}}, TagNoRemotes, "Profile.dial." + TagNoRemotes},
		{"credentials missing", &Profile{Config: &openvpn.Config{}, Remotes: threeRemotes(), NeedsCredentials: true},
			TagCredentialsMissing, "Profile.dial." + TagCredentialsMissing},
		{"credentials missing and no Config", &Profile{Remotes: threeRemotes(), NeedsCredentials: true},
			TagCredentialsMissing, "Profile.dial." + TagCredentialsMissing},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, err := row.profile.dial(t.Context(), inOrder, never)
			wantErr(t, err, row.tag, row.route)
		})
	}
	t.Run("through Dial", func(t *testing.T) {
		_, err := (&Profile{}).Dial(t.Context())
		wantErr(t, err, TagNoRemotes, "Profile.Dial->Profile.dial."+TagNoRemotes)
		_, err = (&Profile{Remotes: threeRemotes(), NeedsCredentials: true}).Dial(t.Context())
		wantErr(t, err, TagCredentialsMissing, "Profile.Dial->Profile.dial."+TagCredentialsMissing)
	})
	t.Run("credentials set", func(t *testing.T) {
		d := &fakeDialer{results: []fakeResult{{conn: &openvpn.Conn{}}}}
		p := &Profile{Config: &openvpn.Config{Credentials: credentials}, Remotes: threeRemotes(), NeedsCredentials: true}
		if _, err := p.dial(t.Context(), inOrder, d.dial); err != nil {
			t.Fatalf("dial: %v", err)
		}
	})
}

func TestProfileDialTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &openvpn.Conn{}
		// The first remote does not answer: it gets ConnectTimeout, then the second is tried.
		d := &fakeDialer{results: []fakeResult{{}, {conn: conn}}}
		p := &Profile{Config: &openvpn.Config{}, Remotes: threeRemotes(), ConnectTimeout: 7 * time.Second}
		start := time.Now()
		got, err := p.dial(t.Context(), inOrder, d.dial)
		if err != nil || got != conn {
			t.Fatalf("dial = %v, %v", got, err)
		}
		if elapsed := time.Since(start); elapsed != 7*time.Second {
			t.Errorf("took %v, want the 7 s of the first remote", elapsed)
		}
		if d.calls[0].timeLeft != 7*time.Second || d.calls[1].timeLeft != 7*time.Second {
			t.Errorf("each attempt must start with the whole timeout: %v, %v", d.calls[0].timeLeft, d.calls[1].timeLeft)
		}

		// With no ConnectTimeout the default is used.
		d = &fakeDialer{results: []fakeResult{{conn: conn}}}
		p = &Profile{Config: &openvpn.Config{}, Remotes: threeRemotes()}
		if _, err := p.dial(t.Context(), inOrder, d.dial); err != nil {
			t.Fatalf("dial: %v", err)
		}
		if d.calls[0].timeLeft != DefaultConnectTimeout {
			t.Errorf("timeout = %v, want %v", d.calls[0].timeLeft, DefaultConnectTimeout)
		}

		// A Config that has a ServerPollTimeout of its own keeps it.
		d = &fakeDialer{results: []fakeResult{{conn: conn}}}
		p = &Profile{Config: &openvpn.Config{ServerPollTimeout: 3 * time.Second}, Remotes: threeRemotes(), ConnectTimeout: 9 * time.Second}
		if _, err := p.dial(t.Context(), inOrder, d.dial); err != nil {
			t.Fatalf("dial: %v", err)
		}
		if d.calls[0].timeLeft != 3*time.Second {
			t.Errorf("timeout = %v, want the 3 s of the Config", d.calls[0].timeLeft)
		}
		// The context of the attempt is the caller's: the time of the handshake with a
		// server that has answered is not cut by ConnectTimeout.
		d = &fakeDialer{results: []fakeResult{{conn: conn}}}
		var deadlines int
		p = &Profile{Config: &openvpn.Config{}, Remotes: threeRemotes(), ConnectTimeout: time.Second}
		_, err = p.dial(t.Context(), inOrder, func(ctx context.Context, network, address string, config *openvpn.Config) (*openvpn.Conn, error) {
			if _, ok := ctx.Deadline(); ok {
				deadlines++
			}
			return d.dial(ctx, network, address, config)
		})
		if err != nil || deadlines != 0 {
			t.Errorf("dial = %v; %d attempts had a deadline on their context, want none", err, deadlines)
		}

		// Every remote times out: the error is the one of the last, and the tries are counted.
		d = &fakeDialer{results: []fakeResult{{}, {}, {}}}
		p = &Profile{Config: &openvpn.Config{}, Remotes: threeRemotes(), ConnectTimeout: 2 * time.Second}
		start = time.Now()
		_, err = p.dial(t.Context(), inOrder, d.dial)
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != tagFakeNoAnswer {
			t.Errorf("err = %v, want the one of the last remote, which did not answer", err)
		}
		if appErr, ok := errors.FromError(err); !ok || appErr.Metadata["remotes_tried"] != 3 {
			t.Errorf("metadata of %v", err)
		}
		if elapsed := time.Since(start); elapsed != 6*time.Second {
			t.Errorf("took %v, want 3 x 2 s", elapsed)
		}
	})
}

func TestProfileDialContextDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// The caller gives up while the first remote is tried: no other remote is tried.
		ctx, cancel := context.WithCancel(t.Context())
		d := &fakeDialer{results: []fakeResult{{}, {conn: &openvpn.Conn{}}, {conn: &openvpn.Conn{}}}}
		p := &Profile{Config: &openvpn.Config{}, Remotes: threeRemotes(), ConnectTimeout: time.Minute}
		time.AfterFunc(3*time.Second, cancel)
		start := time.Now()
		conn, err := p.dial(ctx, inOrder, d.dial)
		if conn != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("dial = %v, %v; want the cancellation", conn, err)
		}
		if len(d.calls) != 1 {
			t.Errorf("%d remotes tried, want 1", len(d.calls))
		}
		if elapsed := time.Since(start); elapsed != 3*time.Second {
			t.Errorf("took %v, want 3 s", elapsed)
		}
		if appErr, ok := errors.FromError(err); !ok || appErr.Metadata["remotes_tried"] != 1 || appErr.Metadata["remotes"] != 3 {
			t.Errorf("metadata of %v", err)
		}
	})
}

// The tags of the errors that the fake dial functions of these tests return.
const (
	tagFakeNoAnswer = "FakeNoAnswer"
	tagFakeFail     = "FakeFail"
	tagFakeFirst    = "FakeFirst"
	tagFakeSecond   = "FakeSecond"
	tagFakeThird    = "FakeThird"
)
