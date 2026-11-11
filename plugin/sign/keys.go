package sign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
)

// Pair holds DNSSEC key information, both the public and private components are stored here.
type Pair struct {
	Public  *dns.DNSKEY
	KeyTag  uint16
	Private crypto.Signer

	// base is the filesystem path of the key pair without the .key/.private
	// extension, so the pair can be re-read on every signing run.
	base string
	// timing holds the optional lifecycle metadata (Publish, Activate,
	// Inactive, Delete) parsed from the BIND key files.
	timing keyTiming
}

// keyParse reads the public and private key from disk.
func keyParse(c *caddy.Controller) ([]Pair, error) {
	if !c.NextArg() {
		return nil, c.ArgErr()
	}
	pairs := []Pair{}
	config := dnsserver.GetConfig(c)

	switch c.Val() {
	case "file":
		ks := c.RemainingArgs()
		if len(ks) == 0 {
			return nil, c.ArgErr()
		}
		for _, k := range ks {
			base := k
			// Kmiek.nl.+013+26205.key, handle .private or without extension: Kmiek.nl.+013+26205
			if strings.HasSuffix(k, ".key") {
				base = k[:len(k)-4]
			}
			if strings.HasSuffix(k, ".private") {
				base = k[:len(k)-8]
			}
			if !filepath.IsAbs(base) && config.Root != "" {
				base = filepath.Join(config.Root, base)
			}

			pair, err := readKeyPair(base+".key", base+".private")
			if err != nil {
				return nil, err
			}
			pair.base = base
			pairs = append(pairs, pair)
		}
	case "directory":
		return nil, fmt.Errorf("directory: not implemented")
	}

	return pairs, nil
}

func readKeyPair(public, private string) (Pair, error) {
	rk, err := os.Open(filepath.Clean(public))
	if err != nil {
		return Pair{}, err
	}
	b, err := io.ReadAll(rk)
	if err != nil {
		return Pair{}, err
	}
	dnskey, err := dns.NewRR(string(b))
	if err != nil {
		return Pair{}, err
	}
	if _, ok := dnskey.(*dns.DNSKEY); !ok {
		return Pair{}, fmt.Errorf("RR in %q is not a DNSKEY: %d", public, dnskey.Header().Rrtype)
	}
	ksk := dnskey.(*dns.DNSKEY).Flags&(1<<8) == (1<<8) && dnskey.(*dns.DNSKEY).Flags&1 == 1
	if !ksk {
		return Pair{}, fmt.Errorf("DNSKEY in %q is not a CSK/KSK", public)
	}

	rp, err := os.Open(filepath.Clean(private))
	if err != nil {
		return Pair{}, err
	}
	pb, err := io.ReadAll(rp)
	if err != nil {
		return Pair{}, err
	}
	privkey, err := dnskey.(*dns.DNSKEY).ReadPrivateKey(bytes.NewReader(pb), private)
	if err != nil {
		return Pair{}, err
	}
	timing, err := parseKeyTiming(b, pb)
	if err != nil {
		return Pair{}, fmt.Errorf("key %q: %w", public, err)
	}
	switch signer := privkey.(type) {
	case *ecdsa.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), KeyTag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer, timing: timing}, nil
	case ed25519.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), KeyTag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer, timing: timing}, nil
	case *rsa.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), KeyTag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer, timing: timing}, nil
	default:
		return Pair{}, fmt.Errorf("unsupported algorithm %s", signer)
	}
}

// reloadKeys re-reads every configured key pair from disk. Lifecycle timing is
// evaluated on every signing run and a temporarily unreadable key file makes
// the signing run fail so the previous complete signed zone stays in place.
func (s *Signer) reloadKeys() ([]Pair, error) {
	pairs := make([]Pair, 0, len(s.keys))
	for _, k := range s.keys {
		p, err := readKeyPair(k.base+".key", k.base+".private")
		if err != nil {
			return nil, fmt.Errorf("failed to read key pair %q: %w", k.base, err)
		}
		p.Public.Header().Name = s.origin
		pairs = append(pairs, p)
	}
	return pairs, nil
}

// keyTag returns the key tags of the keys in ps as a formatted string.
func keyTag(ps []Pair) string {
	if len(ps) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, p := range ps {
		sb.WriteString(strconv.Itoa(int(p.KeyTag)) + ",")
	}
	s := sb.String()
	return s[:len(s)-1]
}
