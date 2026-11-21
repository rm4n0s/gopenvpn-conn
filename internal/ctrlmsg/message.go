// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/push.c (incoming_push_message, process_incoming_push_msg) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package ctrlmsg

import (
	"strconv"
	"strings"

	"github.com/rm4n0s/errors"
)

// PushRequest is the text of the message that asks the server for the settings.
const PushRequest = "PUSH_REQUEST"

// Exit is the text of the message by which a peer says that it has ended the
// session. A client sends it from Close when the server pushed cc-exit, and a
// server sends it when it stops.
const Exit = "EXIT"

// AppendMessage appends a text message to dst as the control channel carries
// it: the text and a NUL. Each message is written to TLS in one Write, so it is
// one record.
func AppendMessage(dst []byte, text string) []byte {
	dst = append(dst, text...)
	return append(dst, 0)
}

// Name is the first word of a message or an option: what is safe to put in a
// log line when the rest could be a secret.
func Name(text string) string {
	name, _, _ := strings.Cut(text, " ")
	name, _, _ = strings.Cut(name, ",")
	if len(name) > 40 {
		name = name[:40]
	}
	return name
}

// PushReply is one message of the server's answer to PUSH_REQUEST. A long reply
// comes in parts: every part but the last ends with the option
// "push-continuation 2".
type PushReply struct {
	// Options are the options of this part, without push-continuation.
	Options []string
	// More is true when the part ends with "push-continuation 2": another part
	// follows.
	More bool
}

// IsPushReply reports whether a message is a PUSH_REPLY.
func IsPushReply(text string) bool {
	return text == "PUSH_REPLY" || strings.HasPrefix(text, "PUSH_REPLY,")
}

// ParsePushReply parses a message that IsPushReply: the options are separated by
// commas. The option "push-continuation N" says whether more parts follow: 2 for
// more, 1 (or nothing) for the last.
//
// Draft: "PUSH_REPLY". OpenVPN: push.c process_incoming_push_reply.
func ParsePushReply(text string) (*PushReply, error) {
	rest, ok := strings.CutPrefix(text, "PUSH_REPLY")
	if !ok || (rest != "" && rest[0] != ',') {
		return nil, errors.New(tagBadMessage, "the message is not a PUSH_REPLY", "name", Name(text))
	}
	r := &PushReply{}
	if rest == "" {
		return r, nil
	}
	for _, opt := range strings.Split(rest[1:], ",") {
		if opt == "" {
			continue
		}
		if value, ok := strings.CutPrefix(opt, "push-continuation "); ok {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || (n != 1 && n != 2) {
				return nil, errors.New(tagBadPushedOption, "push-continuation is not 1 or 2", "option", "push-continuation")
			}
			r.More = n == 2
			continue
		}
		r.Options = append(r.Options, opt)
	}
	return r, nil
}

const tagBadMessage = "BadControlMessage"
