package sign

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"time"
)

// keyTiming holds the optional BIND9 key lifecycle timing metadata read from a
// key pair. A value with all has* flags false means the key carries no
// lifecycle metadata and is always published and used for signing.
type keyTiming struct {
	publish  time.Time
	activate time.Time
	inactive time.Time
	delete   time.Time

	hasPublish  bool
	hasActivate bool
	hasInactive bool
	hasDelete   bool
}

// managed reports whether any lifecycle timing field is present.
func (t keyTiming) managed() bool {
	return t.hasPublish || t.hasActivate || t.hasInactive || t.hasDelete
}

// set stores when for the named lifecycle field (Publish, Activate, Inactive
// or Delete, case-insensitive).
func (t *keyTiming) set(field string, when time.Time) {
	switch strings.ToLower(field) {
	case "publish":
		t.publish, t.hasPublish = when, true
	case "activate":
		t.activate, t.hasActivate = when, true
	case "inactive":
		t.inactive, t.hasInactive = when, true
	case "delete":
		t.delete, t.hasDelete = when, true
	}
}

// validate checks the ordering of the timing fields that are present:
// Publish <= Activate <= Inactive <= Delete.
func (t keyTiming) validate() error {
	type edge struct {
		name string
		when time.Time
		set  bool
	}
	edges := []edge{
		{"Publish", t.publish, t.hasPublish},
		{"Activate", t.activate, t.hasActivate},
		{"Inactive", t.inactive, t.hasInactive},
		{"Delete", t.delete, t.hasDelete},
	}
	var prev edge
	havePrev := false
	for _, e := range edges {
		if !e.set {
			continue
		}
		if havePrev && e.when.Before(prev.when) {
			return fmt.Errorf("invalid key timing: %s (%s) is before %s (%s)", e.name, e.when.UTC().Format(timeFmt), prev.name, prev.when.UTC().Format(timeFmt))
		}
		prev, havePrev = e, true
	}
	return nil
}

// keyState is the lifecycle state of a key at a given point in time.
type keyState int

const (
	// keyHidden means the publish time has not been reached yet and the key
	// stays out of the zone.
	keyHidden keyState = iota
	// keyPublished means the DNSKEY is published but the key does not sign yet.
	keyPublished
	// keyActive means the DNSKEY is published and the key signs the zone.
	keyActive
	// keyRetired means the key no longer signs but the DNSKEY is retained until
	// the delete time.
	keyRetired
	// keyRemoved means the delete time has been reached and the key is gone
	// from the zone.
	keyRemoved
)

// stateAt returns the lifecycle state of the key at time now. Keys without any
// lifecycle metadata are always active, preserving the historical behavior
// where every configured key participates in signing.
func (p Pair) stateAt(now time.Time) keyState {
	t := p.timing
	if !t.managed() {
		return keyActive
	}
	if t.hasDelete && !now.Before(t.delete) {
		return keyRemoved
	}
	if t.hasPublish && now.Before(t.publish) {
		return keyHidden
	}
	signing := true
	if t.hasActivate && now.Before(t.activate) {
		signing = false
	}
	if t.hasInactive && !now.Before(t.inactive) {
		signing = false
	}
	if signing {
		return keyActive
	}
	if t.hasActivate && now.Before(t.activate) {
		return keyPublished
	}
	return keyRetired
}

// selectKeys partitions the configured key pairs into the published set
// (DNSKEY, CDS and CDNSKEY records) and the active set (RRSIG generation) at
// time now. It returns an error when no key is allowed to sign, in which case
// the caller must not replace the previously signed zone.
func selectKeys(origin string, pairs []Pair, now time.Time) (published, active []Pair, err error) {
	for _, p := range pairs {
		switch p.stateAt(now) {
		case keyPublished, keyActive, keyRetired:
			published = append(published, p)
		}
		if p.stateAt(now) == keyActive {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return nil, nil, fmt.Errorf("no active signing keys for zone %q at %s; retaining previous signed zone", origin, now.UTC().Format(timeFmt))
	}
	return published, active, nil
}

// parseKeyTiming reads the BIND9 lifecycle timing (Publish, Activate, Inactive
// and Delete) from a key pair. In the public .key file the metadata is carried
// in ';'-comment lines, in the .private file it uses plain "Field: value"
// lines. Timing found in the private file takes precedence over the public one.
func parseKeyTiming(keyFile, privateFile []byte) (keyTiming, error) {
	var t keyTiming
	if err := parseTimingLines(keyFile, true, &t); err != nil {
		return t, err
	}
	if err := parseTimingLines(privateFile, false, &t); err != nil {
		return t, err
	}
	return t, t.validate()
}

// parseTimingLines scans b for lifecycle timing lines. When comments is true
// only ';'-comment lines are considered (public .key file), otherwise plain
// key/value lines are parsed (private key file).
func parseTimingLines(b []byte, comments bool, t *keyTiming) error {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if comments {
			if !strings.HasPrefix(line, ";") {
				continue
			}
			line = strings.TrimSpace(strings.TrimPrefix(line, ";"))
		} else if strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(fields[0], ":"))
		if !isTimingField(name) {
			continue
		}
		when, err := parseKeyTime(fields[1])
		if err != nil {
			return fmt.Errorf("invalid %s timing %q: %w", name, fields[1], err)
		}
		t.set(name, when)
	}
	return sc.Err()
}

func isTimingField(name string) bool {
	switch name {
	case "publish", "activate", "inactive", "delete":
		return true
	}
	return false
}

// parseKeyTime parses the absolute BIND9 timing formats written by
// dnssec-keygen: YYYYMMDDHHMMSS, YYYYMMDD or an RFC 3339 timestamp.
func parseKeyTime(s string) (time.Time, error) {
	switch len(s) {
	case 14:
		if t, err := time.Parse("20060102150405", s); err == nil {
			return t, nil
		}
	case 8:
		if t, err := time.Parse("20060102", s); err == nil {
			return t, nil
		}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("expected YYYYMMDDHHMMSS, YYYYMMDD or RFC3339 timestamp")
}
