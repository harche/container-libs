package signature

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/storage/pkg/configfile"
)

const testBasePolicy = `{
  "default": [{"type": "insecureAcceptAnything"}],
  "transports": {
    "docker": {
      "quay.io": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/base.gpg"}],
      "registry.example.com/blocked": [{"type": "reject"}]
    }
  }
}`

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
}

// loadTestPolicy writes base and fragments (name -> JSON) to a temp dir and loads them.
func loadTestPolicy(t *testing.T, base string, fragments map[string]string) (*Policy, []PolicyScopeSource, error) {
	t.Helper()
	dir := t.TempDir()
	basePath := filepath.Join(dir, "policy.json")
	if base != "" {
		writeFile(t, basePath, base)
	}
	dropIns := filepath.Join(dir, "policy.json.d")
	for name, c := range fragments {
		writeFile(t, filepath.Join(dropIns, name), c)
	}
	conf := &configfile.File{
		Name: "policy", Extension: "json",
		CustomConfigFilePath:            basePath,
		CustomConfigFileDropInDirectory: dropIns,
		ErrorIfNotFound:                 true,
	}
	return loadPolicyWithDropIns(conf)
}

func reqTypes(reqs PolicyRequirements) []string {
	res := []string{}
	for _, r := range reqs {
		switch r := r.(type) {
		case *prSignedBy:
			res = append(res, "signedBy:"+r.KeyPath)
		case *prReject:
			res = append(res, "reject")
		case *prInsecureAcceptAnything:
			res = append(res, "accept")
		default:
			res = append(res, "other")
		}
	}
	return res
}

func TestPolicyDropInsNoFragmentsUnchanged(t *testing.T) {
	p, _, err := loadTestPolicy(t, testBasePolicy, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"signedBy:/base.gpg"}, reqTypes(p.Transports["docker"]["quay.io"]))
	assert.Equal(t, []string{"accept"}, reqTypes(p.Default))
}

func TestPolicyDropInsAddsIndependentScope(t *testing.T) {
	p, src, err := loadTestPolicy(t, testBasePolicy, map[string]string{
		"50-partner.json": `{"transports":{"docker":{"partner.example.com/app":[{"type":"signedBy","keyType":"GPGKeys","keyPath":"/partner.gpg"}]}}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"signedBy:/partner.gpg"}, reqTypes(p.Transports["docker"]["partner.example.com/app"]))
	assert.Equal(t, []string{"signedBy:/base.gpg"}, reqTypes(p.Transports["docker"]["quay.io"]), "base scope untouched")
	for _, s := range src {
		if s.Scope == "partner.example.com/app" {
			assert.Contains(t, s.File, "50-partner.json")
			assert.Empty(t, s.AlsoRequires)
		}
	}
}

func TestPolicyDropInsDuplicateScopeIsError(t *testing.T) {
	frag := `{"transports":{"docker":{"partner.example.com":[{"type":"insecureAcceptAnything"}]}}}`
	_, _, err := loadTestPolicy(t, testBasePolicy, map[string]string{"10-a.json": frag, "20-b.json": frag})
	require.ErrorContains(t, err, "10-a.json")
	require.ErrorContains(t, err, "20-b.json")

	// Duplicate with the base file too.
	_, _, err = loadTestPolicy(t, testBasePolicy, map[string]string{
		"10-a.json": `{"transports":{"docker":{"quay.io":[{"type":"insecureAcceptAnything"}]}}}`,
	})
	require.ErrorContains(t, err, "defined in both")
}

func TestPolicyDropInsCannotWeakenEnclosingScope(t *testing.T) {
	p, src, err := loadTestPolicy(t, testBasePolicy, map[string]string{
		"10-weaken.json":  `{"transports":{"docker":{"quay.io/foo":[{"type":"insecureAcceptAnything"}]}}}`,
		"20-unblock.json": `{"transports":{"docker":{"registry.example.com/blocked/app":[{"type":"insecureAcceptAnything"}]}}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"accept", "signedBy:/base.gpg"}, reqTypes(p.Transports["docker"]["quay.io/foo"]))
	assert.Equal(t, []string{"accept", "reject"}, reqTypes(p.Transports["docker"]["registry.example.com/blocked/app"]))
	for _, s := range src {
		if s.Scope == "quay.io/foo" {
			assert.Equal(t, []string{"docker:quay.io"}, s.AlsoRequires)
		}
	}
}

func TestPolicyDropInsBroaderFragmentTightensNarrowerBaseScope(t *testing.T) {
	base := `{"default":[{"type":"insecureAcceptAnything"}],"transports":{"docker":{
	  "quay.io/org/app":[{"type":"signedBy","keyType":"GPGKeys","keyPath":"/app.gpg"}]}}}`
	p, _, err := loadTestPolicy(t, base, map[string]string{
		"10-org.json": `{"transports":{"docker":{"quay.io/org":[{"type":"signedBy","keyType":"GPGKeys","keyPath":"/org.gpg"}]}}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"signedBy:/app.gpg", "signedBy:/org.gpg"}, reqTypes(p.Transports["docker"]["quay.io/org/app"]))
}

func TestPolicyDropInsDefaultNotInherited(t *testing.T) {
	base := `{"default":[{"type":"reject"}],"transports":{"docker":{"":[{"type":"reject"}]}}}`
	p, _, err := loadTestPolicy(t, base, map[string]string{
		"10-allow.json": `{"transports":{"docker":{"partner.example.com":[{"type":"insecureAcceptAnything"}]}}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"accept"}, reqTypes(p.Transports["docker"]["partner.example.com"]),
		"an allowlist entry under reject-by-default must be possible")
}

func TestPolicyDropInsFragmentValidation(t *testing.T) {
	for name, frag := range map[string]string{
		"default":      `{"default":[{"type":"insecureAcceptAnything"}]}`,
		"empty scope":  `{"transports":{"docker":{"":[{"type":"insecureAcceptAnything"}]}}}`,
		"bad json":     `{"transports":`,
		"unknown key":  `{"transport":{}}`,
		"unknown type": `{"transports":{"docker":{"quay.io/x":[{"type":"bogus"}]}}}`,
		"empty reqs":   `{"transports":{"docker":{"quay.io/x":[]}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := loadTestPolicy(t, testBasePolicy, map[string]string{"10-bad.json": frag})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "10-bad.json")
		})
	}
}

func TestPolicyDropInsWithoutBaseIsError(t *testing.T) {
	_, _, err := loadTestPolicy(t, "", map[string]string{
		"10-a.json": `{"transports":{"docker":{"quay.io/x":[{"type":"insecureAcceptAnything"}]}}}`,
	})
	require.Error(t, err)
}

func TestScopeEncloses(t *testing.T) {
	for _, c := range []struct {
		parent, child string
		want          bool
	}{
		{"quay.io", "quay.io/foo", true},
		{"quay.io/foo", "quay.io/foo/bar", true},
		{"quay.io/foo", "quay.io/foo:tag", true},
		{"quay.io/foo", "quay.io/foo@sha256:abc", true},
		{"quay.io/foo", "quay.io/foobar", false},
		{"quay.io/foo", "quay.io", false},
		{"*.example.com", "reg.example.com/app", true},
		{"*.example.com", "*.sub.example.com", true},
		{"*.example.com", "*.example.com", false},
		{"*.example.com", "example.com/app", false},
	} {
		assert.Equal(t, c.want, scopeEncloses(c.parent, c.child), "%q encloses %q", c.parent, c.child)
	}
}

func TestPolicyDropInsSameFileExemptionKept(t *testing.T) {
	// One fragment (e.g. all ClusterImagePolicies rendered by MCO) requires a key for
	// quay.io/org and exempts quay.io/org/public. Within one file the most specific
	// scope wins, so the exemption works.
	p, src, err := loadTestPolicy(t, testBasePolicy, map[string]string{
		"50-cip.json": `{"transports":{"docker":{
		  "registry.partner.com":[{"type":"signedBy","keyType":"GPGKeys","keyPath":"/partner.gpg"}],
		  "registry.partner.com/public":[{"type":"insecureAcceptAnything"}]}}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"accept"}, reqTypes(p.Transports["docker"]["registry.partner.com/public"]))
	for _, s := range src {
		if s.Scope == "registry.partner.com/public" {
			assert.Empty(t, s.AlsoRequires)
		}
	}
}

func TestPolicyDropInsSameFileExemptionStillBoundByOtherFiles(t *testing.T) {
	// The fragment exempts quay.io/acme/public from its own quay.io/acme/... rule, but the
	// base file (another file) requires /base.gpg for all of quay.io: that still applies.
	p, src, err := loadTestPolicy(t, testBasePolicy, map[string]string{
		"50-acme.json": `{"transports":{"docker":{
		  "quay.io/acme":[{"type":"signedBy","keyType":"GPGKeys","keyPath":"/acme.gpg"}],
		  "quay.io/acme/public":[{"type":"insecureAcceptAnything"}]}}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"signedBy:/acme.gpg", "signedBy:/base.gpg"}, reqTypes(p.Transports["docker"]["quay.io/acme"]))
	assert.Equal(t, []string{"accept", "signedBy:/base.gpg"}, reqTypes(p.Transports["docker"]["quay.io/acme/public"]))
	for _, s := range src {
		if s.Scope == "quay.io/acme/public" {
			assert.Equal(t, []string{"docker:quay.io"}, s.AlsoRequires)
		}
	}
}

func TestPolicyDropInsBaseOnlyUnchanged(t *testing.T) {
	// Base-to-base pairs are a same-file pair: classic semantics, nothing ANDed.
	base := `{"default":[{"type":"insecureAcceptAnything"}],"transports":{"docker":{
	  "quay.io":[{"type":"reject"}],
	  "quay.io/allowed":[{"type":"insecureAcceptAnything"}]}}}`
	p, _, err := loadTestPolicy(t, base, map[string]string{
		"50-other.json": `{"transports":{"docker":{"registry.example.com":[{"type":"insecureAcceptAnything"}]}}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"accept"}, reqTypes(p.Transports["docker"]["quay.io/allowed"]))
}

func TestNewPartialPolicyFromBytes(t *testing.T) {
	p, err := NewPartialPolicyFromBytes([]byte(`{"transports":{"docker":{"quay.io/x":[{"type":"reject"}]}}}`))
	require.NoError(t, err)
	assert.Nil(t, p.Default)
	assert.Equal(t, []string{"reject"}, reqTypes(p.Transports["docker"]["quay.io/x"]))

	p, err = NewPartialPolicyFromBytes([]byte(`{"default":[{"type":"reject"}]}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"reject"}, reqTypes(p.Default))

	for _, bad := range []string{`{"transports":`, `{"bogus":1}`, `{"transports":{"docker":{"quay.io/x":[]}}}`} {
		_, err := NewPartialPolicyFromBytes([]byte(bad))
		assert.Error(t, err, bad)
	}
	assert.True(t, PolicyScopeEncloses("docker", "quay.io", "quay.io/x"))
}
