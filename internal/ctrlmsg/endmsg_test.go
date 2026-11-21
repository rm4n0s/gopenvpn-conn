// SPDX-License-Identifier: GPL-2.0-only

package ctrlmsg

import (
	"strings"
	"testing"
	"time"
)

func TestParseAuthFailed(t *testing.T) {
	tests := []struct {
		text string
		want AuthFailed
	}{
		{"AUTH_FAILED", AuthFailed{}},
		{"AUTH_FAILED,", AuthFailed{}},
		{"AUTH_FAILED,wrong password", AuthFailed{Reason: "wrong password"}},
		{"AUTH_FAILED,SESSION:token expired", AuthFailed{Session: true, Reason: "token expired"}},
		{"AUTH_FAILED,SESSION:", AuthFailed{Session: true}},
		{"AUTH_FAILED,TEMP", AuthFailed{Temporary: true}},
		{"AUTH_FAILED,TEMP:try later", AuthFailed{Temporary: true, Reason: "try later"}},
		{"AUTH_FAILED,TEMP[backoff 42,advance no]:busy", AuthFailed{Temporary: true, Backoff: 42 * time.Second, Advance: "no", Reason: "busy"}},
		{"AUTH_FAILED,TEMP[advance remote]:next", AuthFailed{Temporary: true, Advance: "remote", Reason: "next"}},
		{"AUTH_FAILED,TEMP[advance addr,backoff 5]", AuthFailed{Temporary: true, Advance: "addr", Backoff: 5 * time.Second}},
		{"AUTH_FAILED,TEMP[backoff x]:bad number", AuthFailed{Temporary: true, Reason: "bad number"}},
		{"AUTH_FAILED,TEMP[backoff -4]:negative", AuthFailed{Temporary: true, Reason: "negative"}},
		{"AUTH_FAILED,TEMP[advance sideways,color blue]:unknown flags", AuthFailed{Temporary: true, Reason: "unknown flags"}},
		{"AUTH_FAILED,TEMP[backoff 9:no closing bracket", AuthFailed{Temporary: true, Reason: "[backoff 9:no closing bracket"}},
		{"AUTH_FAILED,CRV1:R,E:abc:def:Enter code", AuthFailed{Reason: "CRV1:R,E:abc:def:Enter code"}},
		{"AUTH_FAILED,TEMPORARY failure", AuthFailed{Temporary: true, Reason: "ORARY failure"}},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			if !IsAuthFailed(tt.text) {
				t.Fatal("IsAuthFailed is false")
			}
			if got := *ParseAuthFailed(tt.text); got != tt.want {
				t.Errorf("= %+v, want %+v", got, tt.want)
			}
		})
	}
	for _, text := range []string{"AUTH_FAILEDX", "AUTH_FAIL", "", "auth_failed", "PUSH_REPLY"} {
		if IsAuthFailed(text) {
			t.Errorf("IsAuthFailed(%q) is true", text)
		}
	}
}

func TestParseAuthFailedKeepsOnlyALimitedReason(t *testing.T) {
	got := ParseAuthFailed("AUTH_FAILED," + strings.Repeat("x", 5000))
	if len(got.Reason) != maxReason {
		t.Errorf("reason is %d bytes, want %d", len(got.Reason), maxReason)
	}
}

func TestParseSignal(t *testing.T) {
	tests := []struct {
		text string
		want Signal
		ok   bool
	}{
		{"HALT", Signal{}, true},
		{"HALT,", Signal{}, true},
		{"HALT,server is going down", Signal{Reason: "server is going down"}, true},
		{"RESTART", Signal{Restart: true}, true},
		{"RESTART,reloading", Signal{Restart: true, Reason: "reloading"}, true},
		{"RESTART,[P]keep", Signal{Restart: true, Flags: "P", Reason: "keep"}, true},
		{"RESTART,[PN]both", Signal{Restart: true, Flags: "PN", Reason: "both"}, true},
		{"RESTART,[N]", Signal{Restart: true, Flags: "N"}, true},
		{"HALT,[P]flags on halt too", Signal{Flags: "P", Reason: "flags on halt too"}, true},
		{"RESTART,[P no bracket", Signal{Restart: true, Reason: "[P no bracket"}, true},
		{"HALTED", Signal{}, false},
		{"RESTARTING,now", Signal{}, false},
		{"PUSH_REPLY", Signal{}, false},
		{"", Signal{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got, ok := ParseSignal(tt.text)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && *got != tt.want {
				t.Errorf("= %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestParseAuthPending(t *testing.T) {
	tests := []struct {
		text string
		want time.Duration
	}{
		{"AUTH_PENDING", 0},
		{"AUTH_PENDING,", 0},
		{"AUTH_PENDING,timeout 120", 120 * time.Second},
		{"AUTH_PENDING,timeout 120,extra thing", 120 * time.Second},
		{"AUTH_PENDING,extra thing,timeout 7", 7 * time.Second},
		{"AUTH_PENDING,timeout x", 0},
		{"AUTH_PENDING,timeout -3", 0},
		{"AUTH_PENDING,timeout 99999999999", 0},
		{"AUTH_PENDING,other", 0},
	}
	for _, tt := range tests {
		if !IsAuthPending(tt.text) {
			t.Errorf("IsAuthPending(%q) is false", tt.text)
		}
		if got := ParseAuthPending(tt.text); got != tt.want {
			t.Errorf("ParseAuthPending(%q) = %v, want %v", tt.text, got, tt.want)
		}
	}
	for _, text := range []string{"AUTH_PENDINGX", "", "AUTH_PEND"} {
		if IsAuthPending(text) {
			t.Errorf("IsAuthPending(%q) is true", text)
		}
	}
}

func FuzzParseEndMessages(f *testing.F) {
	for _, s := range []string{
		"AUTH_FAILED,TEMP[backoff 42,advance no]:busy", "AUTH_FAILED,SESSION:x", "RESTART,[PN]x", "HALT,y", "AUTH_PENDING,timeout 5", "",
		"AUTH_FAILED,TEMP[", "RESTART,[", "AUTH_PENDING,timeout ",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if IsAuthFailed(text) {
			a := ParseAuthFailed(text)
			if len(a.Reason) > maxReason || a.Backoff < 0 || (a.Session && a.Temporary) {
				t.Fatalf("a bad result: %+v", a)
			}
		}
		if s, ok := ParseSignal(text); ok && len(s.Reason) > maxReason {
			t.Fatalf("a reason of %d bytes", len(s.Reason))
		}
		if d := ParseAuthPending(text); d < 0 {
			t.Fatalf("a negative time: %v", d)
		}
	})
}
