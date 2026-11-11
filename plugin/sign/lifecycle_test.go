package sign

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"

	"github.com/miekg/dns"
)

// fixed "now" used across the lifecycle tests, all key timing is arranged
// around this date.
var lifecycleNow = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

const lifecycleTimeLayout = "20060102150405"

func lifecycleTime(y int, mo time.Month, d, h, min int) string {
	return time.Date(y, mo, d, h, min, 0, 0, time.UTC).Format(lifecycleTimeLayout)
}

// stripTimingLines removes Publish/Activate/Inactive/Delete lines from key file
// content. commentLine selects the public .key format (';'-comments) versus the
// private key format (plain key/value lines).
func stripTimingLines(b []byte, commentLine bool) []byte {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if commentLine {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, ";"))
		}
		fields := strings.Fields(trimmed)
		if len(fields) > 0 && isTimingField(strings.ToLower(strings.TrimSuffix(fields[0], ":"))) {
			continue
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n"))
}

func appendTiming(b []byte, timing map[string]string, commentLine bool) []byte {
	var sb strings.Builder
	sb.Write(b)
	if len(b) > 0 && b[len(b)-1] != '\n' {
		sb.WriteByte('\n')
	}
	for field, when := range timing {
		if commentLine {
			fmt.Fprintf(&sb, "; %s: %s\n", field, when)
		} else {
			fmt.Fprintf(&sb, "%s: %s\n", field, when)
		}
	}
	return []byte(sb.String())
}

// writeTimedKey copies the deterministic testdata key pair into dir and
// attaches the given lifecycle timing. It returns the base path.
func writeTimedKey(t *testing.T, dir, base string, timing map[string]string) string {
	t.Helper()
	keyBytes, err := os.ReadFile("testdata/Kmiek.nl.+013+59725.key")
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := os.ReadFile("testdata/Kmiek.nl.+013+59725.private")
	if err != nil {
		t.Fatal(err)
	}
	keyBytes = appendTiming(stripTimingLines(keyBytes, true), timing, true)
	privBytes = appendTiming(stripTimingLines(privBytes, false), timing, false)

	keyPath := filepath.Join(dir, base+".key")
	privPath := filepath.Join(dir, base+".private")
	if err := os.WriteFile(keyPath, keyBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privPath, privBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, base)
}

// generateTimedKey creates a fresh ECDSAP256SHA256 KSK pair in dir, distinct
// from the testdata key tag, and attaches the given lifecycle timing.
func generateTimedKey(t *testing.T, dir, base string, timing map[string]string) string {
	t.Helper()
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := dnskey.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv := priv.(*ecdsa.PrivateKey)

	var keyContent, privContent strings.Builder
	for field, when := range timing {
		fmt.Fprintf(&keyContent, "; %s: %s\n", field, when)
		fmt.Fprintf(&privContent, "%s: %s\n", field, when)
	}
	keyContent.WriteString(dnskey.String())
	keyContent.WriteByte('\n')

	privContent.WriteString("Private-key-format: v1.3\n")
	privContent.WriteString("Algorithm: 13 (ECDSAP256SHA256)\n")
	privContent.WriteString("PrivateKey: ")
	privContent.WriteString(base64.StdEncoding.EncodeToString(ecPriv.D.FillBytes(make([]byte, 32))))
	privContent.WriteByte('\n')

	if err := os.WriteFile(filepath.Join(dir, base+".key"), []byte(keyContent.String()), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, base+".private"), []byte(privContent.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, base)
}

func signerWithKeys(t *testing.T, dir string, bases ...string) *Signer {
	t.Helper()
	var sb strings.Builder
	for _, b := range bases {
		fmt.Fprintf(&sb, "\t\tkey file %s\n", b)
	}
	input := fmt.Sprintf("sign testdata/db.miek.nl miek.nl {\n%s\t\tdirectory %s\n\t}", sb.String(), dir)
	c := caddy.NewTestController("dns", input)
	sign, err := parse(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(sign.signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(sign.signers))
	}
	return sign.signers[0]
}

func keyTags(rrs []dns.RR) map[uint16]bool {
	tags := map[uint16]bool{}
	for _, rr := range rrs {
		tags[rr.(*dns.RRSIG).KeyTag] = true
	}
	return tags
}

func TestParseKeyTiming(t *testing.T) {
	tests := []struct {
		name        string
		keyFile     string
		privateFile string
		want        keyTiming
		shouldErr   bool
	}{
		{
			name: "all fields in public key comments",
			keyFile: `; Created: 20200101000000 (Wed Jan  1 00:00:00 2020)
; Publish: 20200101000000 (Wed Jan  1 00:00:00 2020)
; Activate: 20200201000000
; Inactive: 20200301000000
; Delete: 20200401000000
miek.nl. IN DNSKEY 257 3 13 abc=
`,
			privateFile: `Private-key-format: v1.3
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: x
`,
			want: keyTiming{
				hasPublish: true, publish: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
				hasActivate: true, activate: time.Date(2020, 2, 1, 0, 0, 0, 0, time.UTC),
				hasInactive: true, inactive: time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC),
				hasDelete: true, delete: time.Date(2020, 4, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name:    "fields in private file and eight digit date",
			keyFile: "miek.nl. IN DNSKEY 257 3 13 abc=\n",
			privateFile: `Private-key-format: v1.3
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: x
Publish: 20200101
Activate: 20200102
`,
			want: keyTiming{
				hasPublish:  true,
				publish:     time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
				hasActivate: true,
				activate:    time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name:        "no metadata means unmanaged",
			keyFile:     "miek.nl. IN DNSKEY 257 3 13 abc=\n",
			privateFile: "Private-key-format: v1.3\nPrivateKey: x\n",
			want:        keyTiming{},
		},
		{
			name: "sync timing fields are ignored",
			keyFile: `; SyncPublish: 20200101000000
; SyncDelete: 20200401000000
miek.nl. IN DNSKEY 257 3 13 abc=
`,
			privateFile: "Private-key-format: v1.3\nPrivateKey: x\n",
			want:        keyTiming{},
		},
		{
			name: "private file overrides public file",
			keyFile: `; Publish: 20200101000000
miek.nl. IN DNSKEY 257 3 13 abc=
`,
			privateFile: `Private-key-format: v1.3
PrivateKey: x
Publish: 20200202000000
`,
			want: keyTiming{hasPublish: true, publish: time.Date(2020, 2, 2, 0, 0, 0, 0, time.UTC)},
		},
		{
			name: "invalid timestamp",
			keyFile: `; Publish: not-a-date
miek.nl. IN DNSKEY 257 3 13 abc=
`,
			privateFile: "Private-key-format: v1.3\nPrivateKey: x\n",
			shouldErr:   true,
		},
		{
			name: "inactive before activate is rejected",
			keyFile: `; Activate: 20200301000000
; Inactive: 20200201000000
miek.nl. IN DNSKEY 257 3 13 abc=
`,
			privateFile: "Private-key-format: v1.3\nPrivateKey: x\n",
			shouldErr:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseKeyTiming([]byte(tc.keyFile), []byte(tc.privateFile))
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error, got timing %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("timing mismatch:\nwant %+v\ngot  %+v", tc.want, got)
			}
		})
	}
}

func TestKeyStateAt(t *testing.T) {
	timing := keyTiming{
		hasPublish:  true,
		publish:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		hasActivate: true,
		activate:    time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
		hasInactive: true,
		inactive:    time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
		hasDelete:   true,
		delete:      time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC),
	}
	p := Pair{timing: timing}

	tests := []struct {
		when time.Time
		want keyState
	}{
		{time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC), keyHidden},
		{time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), keyPublished}, // publish boundary, before activate
		{time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC), keyPublished},
		{time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), keyActive}, // activate boundary
		{time.Date(2025, 2, 15, 0, 0, 0, 0, time.UTC), keyActive},
		{time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC), keyRetired}, // inactive boundary
		{time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC), keyRetired},
		{time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC), keyRemoved}, // delete boundary
		{time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC), keyRemoved},
	}
	for _, tc := range tests {
		if got := p.stateAt(tc.when); got != tc.want {
			t.Errorf("stateAt(%s): want %d, got %d", tc.when.Format(lifecycleTimeLayout), tc.want, got)
		}
	}

	// A key without lifecycle metadata is always active.
	if got := (Pair{}).stateAt(lifecycleNow); got != keyActive {
		t.Errorf("unmanaged key: want %d, got %d", keyActive, got)
	}
}

func TestSelectKeys(t *testing.T) {
	hidden := Pair{KeyTag: 1, timing: keyTiming{hasPublish: true, publish: lifecycleNow.Add(time.Hour), hasActivate: true, activate: lifecycleNow.Add(2 * time.Hour)}}
	published := Pair{KeyTag: 2, timing: keyTiming{hasPublish: true, publish: lifecycleNow.Add(-time.Hour), hasActivate: true, activate: lifecycleNow.Add(time.Hour)}}
	active := Pair{KeyTag: 3, timing: keyTiming{hasActivate: true, activate: lifecycleNow.Add(-time.Hour)}}
	retired := Pair{KeyTag: 4, timing: keyTiming{hasInactive: true, inactive: lifecycleNow.Add(-time.Hour), hasDelete: true, delete: lifecycleNow.Add(time.Hour)}}
	removed := Pair{KeyTag: 5, timing: keyTiming{hasDelete: true, delete: lifecycleNow.Add(-time.Hour)}}
	unmanaged := Pair{KeyTag: 6}

	pub, act, err := selectKeys("miek.nl.", []Pair{hidden, published, active, retired, removed, unmanaged}, lifecycleNow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pub) != 4 {
		t.Errorf("expected 4 published keys, got %d", len(pub))
	}
	if len(act) != 2 {
		t.Errorf("expected 2 active keys, got %d", len(act))
	}
	activeTags := keyTagsFromPairs(act)
	if !activeTags[3] || !activeTags[6] {
		t.Errorf("expected tags 3 and 6 active, got %v", activeTags)
	}

	// No active key at all: signing must be refused.
	if _, _, err := selectKeys("miek.nl.", []Pair{hidden, removed}, lifecycleNow); err == nil {
		t.Fatal("expected error when no key is active")
	}
}

func keyTagsFromPairs(ps []Pair) map[uint16]bool {
	tags := map[uint16]bool{}
	for _, p := range ps {
		tags[p.KeyTag] = true
	}
	return tags
}

func TestSignLifecycleRollover(t *testing.T) {
	dir := t.TempDir()
	// Old key: retired at lifecycleNow (inactive passed, delete in the future).
	oldBase := writeTimedKey(t, dir, "Kold.+013+11111", map[string]string{
		"Publish":  lifecycleTime(2020, 1, 1, 0, 0),
		"Activate": lifecycleTime(2020, 1, 1, 0, 0),
		"Inactive": lifecycleTime(2025, 1, 1, 0, 0),
		"Delete":   lifecycleTime(2026, 1, 1, 0, 0),
	})
	// New key: active at lifecycleNow, distinct key tag.
	newBase := generateTimedKey(t, dir, "Knew.+013+22222", map[string]string{
		"Publish":  lifecycleTime(2025, 5, 1, 0, 0),
		"Activate": lifecycleTime(2025, 5, 15, 0, 0),
	})
	s := signerWithKeys(t, dir, oldBase, newBase)

	z, err := s.Sign(lifecycleNow)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	apex, _ := z.Search("miek.nl.")
	if x := len(apex.Type(dns.TypeDNSKEY)); x != 2 {
		t.Errorf("expected 2 DNSKEY (parallel retention), got %d", x)
	}
	if x := len(apex.Type(dns.TypeCDS)); x != 4 {
		t.Errorf("expected 4 CDS, got %d", x)
	}
	if x := len(apex.Type(dns.TypeCDNSKEY)); x != 2 {
		t.Errorf("expected 2 CDNSKEY, got %d", x)
	}
	newTag := s.keys[1].KeyTag
	if x := len(z.SIGSOA); x != 1 {
		t.Fatalf("expected 1 SOA RRSIG, got %d", x)
	}
	if z.SIGSOA[0].(*dns.RRSIG).KeyTag != newTag {
		t.Errorf("SOA must be signed by the new active key %d, got %d", newTag, z.SIGSOA[0].(*dns.RRSIG).KeyTag)
	}
	var dnskeySigs []dns.RR
	for _, rr := range apex.Type(dns.TypeRRSIG) {
		if rr.(*dns.RRSIG).TypeCovered == dns.TypeDNSKEY {
			dnskeySigs = append(dnskeySigs, rr)
		}
	}
	if len(dnskeySigs) != 1 || dnskeySigs[0].(*dns.RRSIG).KeyTag != newTag {
		t.Errorf("DNSKEY RRset must be signed only by new key, got %v", keyTags(dnskeySigs))
	}
}

func TestSignLifecyclePrePublication(t *testing.T) {
	dir := t.TempDir()
	// Old key still active, new key published but not activated yet.
	oldBase := writeTimedKey(t, dir, "Kold.+013+11111", map[string]string{
		"Publish":  lifecycleTime(2020, 1, 1, 0, 0),
		"Activate": lifecycleTime(2020, 1, 1, 0, 0),
	})
	newBase := generateTimedKey(t, dir, "Knew.+013+22222", map[string]string{
		"Publish":  lifecycleTime(2025, 5, 1, 0, 0),
		"Activate": lifecycleTime(2025, 7, 1, 0, 0),
	})
	s := signerWithKeys(t, dir, oldBase, newBase)

	z, err := s.Sign(lifecycleNow)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	apex, _ := z.Search("miek.nl.")
	if x := len(apex.Type(dns.TypeDNSKEY)); x != 2 {
		t.Errorf("expected pre-published new DNSKEY, got %d DNSKEY", x)
	}
	oldTag := s.keys[0].KeyTag
	if x := len(z.SIGSOA); x != 1 || z.SIGSOA[0].(*dns.RRSIG).KeyTag != oldTag {
		t.Errorf("SOA must still be signed by old key %d, got %v", oldTag, keyTags(z.SIGSOA))
	}
}

func TestSignLifecycleHiddenAndRemoved(t *testing.T) {
	dir := t.TempDir()
	hiddenBase := writeTimedKey(t, dir, "Kfuture.+013+33333", map[string]string{
		"Publish":  lifecycleTime(2026, 1, 1, 0, 0),
		"Activate": lifecycleTime(2026, 2, 1, 0, 0),
	})
	removedBase := generateTimedKey(t, dir, "Kgone.+013+44444", map[string]string{
		"Publish":  lifecycleTime(2020, 1, 1, 0, 0),
		"Activate": lifecycleTime(2020, 1, 1, 0, 0),
		"Delete":   lifecycleTime(2025, 1, 1, 0, 0),
	})
	activeBase := generateTimedKey(t, dir, "Kcurrent.+013+55555", map[string]string{
		"Publish":  lifecycleTime(2025, 5, 1, 0, 0),
		"Activate": lifecycleTime(2025, 5, 1, 0, 0),
	})
	s := signerWithKeys(t, dir, hiddenBase, removedBase, activeBase)

	z, err := s.Sign(lifecycleNow)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	apex, _ := z.Search("miek.nl.")
	if x := len(apex.Type(dns.TypeDNSKEY)); x != 1 {
		t.Errorf("expected only the active DNSKEY, got %d", x)
	}
	activeTag := s.keys[2].KeyTag
	if x := len(z.SIGSOA); x != 1 || z.SIGSOA[0].(*dns.RRSIG).KeyTag != activeTag {
		t.Errorf("SOA must be signed by active key %d, got %v", activeTag, keyTags(z.SIGSOA))
	}
}

func TestSignNoLifecycleMetadataCompatible(t *testing.T) {
	dir := t.TempDir()
	// Copied key with every lifecycle line stripped.
	base := writeTimedKey(t, dir, "Kplain.+013+59725", nil)
	s := signerWithKeys(t, dir, base)

	z, err := s.Sign(lifecycleNow)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	apex, _ := z.Search("miek.nl.")
	if x := len(apex.Type(dns.TypeDNSKEY)); x != 1 {
		t.Errorf("expected 1 DNSKEY, got %d", x)
	}
	if x := len(apex.Type(dns.TypeCDS)); x != 2 {
		t.Errorf("expected 2 CDS, got %d", x)
	}
	if x := len(apex.Type(dns.TypeCDNSKEY)); x != 1 {
		t.Errorf("expected 1 CDNSKEY, got %d", x)
	}
	if len(z.SIGSOA) != 1 {
		t.Errorf("expected 1 SOA RRSIG, got %d", len(z.SIGSOA))
	}
}

func TestSignRetainsPreviousOnFailure(t *testing.T) {
	dir := t.TempDir()
	base := writeTimedKey(t, dir, "Kretain.+013+59725", nil)
	s := signerWithKeys(t, dir, base)

	z, err := s.Sign(lifecycleNow)
	if err != nil {
		t.Fatalf("initial Sign failed: %v", err)
	}
	if err := s.write(z); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	signedPath := filepath.Join(s.directory, s.signedfile)
	good, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	goodHash := sha256.Sum256(good)

	// Key file temporarily unreadable: signing must fail and leave the previous
	// complete signed zone untouched.
	s.keys[0].base = filepath.Join(dir, "does-not-exist")
	if _, err := s.Sign(lifecycleNow.Add(time.Hour)); err == nil {
		t.Fatal("expected error when key file is unreadable")
	}
	keep, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256(keep); h != goodHash {
		t.Error("previous signed zone was modified while key file was unreadable")
	}

	// Key readable again, but not yet active: signing must still be refused and
	// the previous signed zone retained.
	s.keys[0].base = base
	writeTimedKey(t, dir, "Kretain.+013+59725", map[string]string{
		"Publish":  lifecycleTime(2026, 1, 1, 0, 0),
		"Activate": lifecycleTime(2026, 2, 1, 0, 0),
	})
	if _, err := s.Sign(lifecycleNow.Add(2 * time.Hour)); err == nil {
		t.Fatal("expected error when no key is active yet")
	}
	keep, err = os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256(keep); h != goodHash {
		t.Error("previous signed zone was modified while no key was active")
	}
}

func TestSignLifecycleRestartConvergence(t *testing.T) {
	dir := t.TempDir()
	oldBase := writeTimedKey(t, dir, "Kold.+013+11111", map[string]string{
		"Publish":  lifecycleTime(2020, 1, 1, 0, 0),
		"Activate": lifecycleTime(2020, 1, 1, 0, 0),
		"Inactive": lifecycleTime(2025, 1, 1, 0, 0),
		"Delete":   lifecycleTime(2026, 1, 1, 0, 0),
	})
	newBase := generateTimedKey(t, dir, "Knew.+013+22222", map[string]string{
		"Publish":  lifecycleTime(2025, 5, 1, 0, 0),
		"Activate": lifecycleTime(2025, 5, 15, 0, 0),
	})

	snapshot := func(t *testing.T) (dnskeys map[uint16]bool, soaSigs, apexSigs map[uint16]bool, serial uint32) {
		s := signerWithKeys(t, dir, oldBase, newBase)
		z, err := s.Sign(lifecycleNow)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		apex, _ := z.Search("miek.nl.")
		dnskeys = map[uint16]bool{}
		for _, rr := range apex.Type(dns.TypeDNSKEY) {
			dnskeys[rr.(*dns.DNSKEY).KeyTag()] = true
		}
		return dnskeys, keyTags(z.SIGSOA), keyTags(apex.Type(dns.TypeRRSIG)), z.SOA.Serial
	}

	firstKeys, firstSOA, firstApex, firstSerial := snapshot(t)
	// A fresh signer simulates a restart with the same key files on disk.
	secondKeys, secondSOA, secondApex, secondSerial := snapshot(t)

	if fmt.Sprint(secondKeys) != fmt.Sprint(firstKeys) {
		t.Errorf("DNSKEY set diverged after restart: %v vs %v", firstKeys, secondKeys)
	}
	if fmt.Sprint(secondSOA) != fmt.Sprint(firstSOA) {
		t.Errorf("SOA RRSIG key tags diverged after restart: %v vs %v", firstSOA, secondSOA)
	}
	if fmt.Sprint(secondApex) != fmt.Sprint(firstApex) {
		t.Errorf("apex RRSIG key tags diverged after restart: %v vs %v", firstApex, secondApex)
	}
	if secondSerial != firstSerial {
		t.Errorf("SOA serial diverged at the same point in time: %d vs %d", firstSerial, secondSerial)
	}
}
