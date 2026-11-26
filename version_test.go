// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"os"
	"regexp"
	"testing"
)

// versionLine is the line that ends every entry of docs/IMPLEMENTED.md that
// makes a release: - **Version:** `v1.0.4`
var versionLine = regexp.MustCompile("(?m)^- \\*\\*Version:\\*\\* `v(\\d+)\\.(\\d+)\\.(\\d+)`")

// newestRecorded returns the highest version of the "Version" lines of a log,
// without the "v", or "" when it has none.
func newestRecorded(log string) string {
	best, bestText := [3]int{-1, 0, 0}, ""
	for _, m := range versionLine.FindAllStringSubmatch(log, -1) {
		var v [3]int
		for i := range v {
			for _, c := range m[i+1] {
				v[i] = v[i]*10 + int(c-'0')
			}
		}
		if v[0] > best[0] || v[0] == best[0] && (v[1] > best[1] || v[1] == best[1] && v[2] > best[2]) {
			best, bestText = v, m[1]+"."+m[2]+"."+m[3]
		}
	}
	return bestText
}

func TestNewestRecorded(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want string
	}{
		{"no release line", "## Step 1.1\n- **Built:** x\n", ""},
		{"one", "- **Version:** `v1.0.3`.\n", "1.0.3"},
		{"the highest, not the last", "- **Version:** `v1.0.10`\n- **Version:** `v1.2.0`\n- **Version:** `v1.0.3`, text\n", "1.2.0"},
		{"numbers, not text", "- **Version:** `v1.0.9`\n- **Version:** `v1.0.10`\n", "1.0.10"},
		{"a version in the middle of a line is not a release line", "- **Notes:** `v9.9.9`; - **Version:** `v9.9.9`\n- **Version:** `v1.0.1`\n", "1.0.1"},
		{"a pre-release is not a release line", "- **Version:** `v1.0.0-rc.1`\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newestRecorded(tt.log); got != tt.want {
				t.Errorf("newestRecorded = %q, want %q", got, tt.want)
			}
		})
	}
}

// IV_VER is the version of the release that the server sees. Every release
// changes the constant with its tag (docs/IMPLEMENTATION.md, rule 5), and the
// entry of the release in docs/IMPLEMENTED.md ends with its Version line. The
// test fails for a release whose entry was written and whose constant was not.
func TestLibraryVersionIsTheNewestRelease(t *testing.T) {
	log, err := os.ReadFile("docs/IMPLEMENTED.md")
	if err != nil {
		t.Fatal(err)
	}
	want := newestRecorded(string(log))
	if want == "" {
		t.Fatal("docs/IMPLEMENTED.md has no line of the form: - **Version:** `v1.2.3`")
	}
	if libraryVersion != want {
		t.Errorf("libraryVersion = %q, but the newest release that docs/IMPLEMENTED.md records is v%s: change the constant in conn.go to %q", libraryVersion, want, want)
	}
}

// OpenVPN's server reads a line of the peer info only if the name is made of
// letters, digits and "_" (misc.c validate_peer_info_line), and it keeps 255
// bytes of the line (output_peer_info_env). The version is three numbers.
func TestLibraryVersionFitsThePeerInfo(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(libraryVersion) {
		t.Errorf("libraryVersion = %q, want major.minor.patch with no \"v\"", libraryVersion)
	}
	line := "IV_VER=gopenvpn-conn " + libraryVersion
	if len(line) > 255 {
		t.Errorf("the IV_VER line has %d bytes: the server keeps 255", len(line))
	}
}
