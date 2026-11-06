// policy_dropins.go implements composition of the base policy.json with
// drop-in policy fragments (policy.json.d/*.json).
//
// PROOF OF CONCEPT. Semantics (additive-only, fail-closed):
//
//  1. Fragments are read in the configfile order (lexical by basename; a file
//     in a higher-priority directory replaces a lower-priority file with the
//     same basename).
//  2. A (transport, scope) may be defined by exactly one file. Defining it in
//     two files is an error that names both files.
//  3. Only the base policy may set "default" or a transport-wide "" scope.
//  4. Inheritance across files: a scope also gets (ANDs) the requirements of
//     the nearest enclosing explicit scope that is defined in a DIFFERENT
//     file. A file can therefore never weaken another file's rule. Within one
//     file the classic "most specific scope wins" semantics apply, so a file
//     can exempt a sub-scope from its own broader rule, and existing
//     single-file policies behave exactly as before. "default" and "" are not
//     inherited: they describe images nobody configured explicitly.

package signature

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	"go.podman.io/image/v5/signature/internal"
	"go.podman.io/image/v5/types"
	"go.podman.io/storage/pkg/configfile"
	"go.podman.io/storage/pkg/unshare"
)

// PolicyScopeSource describes where the effective requirements of one
// (transport, scope) in a composed policy came from.
type PolicyScopeSource struct {
	Transport string
	Scope     string
	// File is the policy file that defines this scope.
	File string
	// AlsoRequires lists enclosing scopes ("transport:scope", nearest first)
	// whose requirements were ANDed into this scope.
	AlsoRequires []string
}

// policyFragment is a parsed drop-in fragment: a policy without "default".
type policyFragment struct {
	name       string
	transports map[string]PolicyTransportScopes
}

// newPolicyFragmentFromBytes parses a drop-in fragment.
func newPolicyFragmentFromBytes(data []byte) (map[string]PolicyTransportScopes, error) {
	var def json.RawMessage
	transports := policyTransportsMap{}
	if err := internal.ParanoidUnmarshalJSONObject(data, func(key string) any {
		switch key {
		case "default":
			return &def
		case "transports":
			return &transports
		default:
			return nil
		}
	}); err != nil {
		return nil, InvalidPolicyFormatError(err.Error())
	}
	if def != nil {
		return nil, InvalidPolicyFormatError(`"default" may only be set in the base policy, not in a drop-in fragment`)
	}
	for transport, scopes := range transports {
		if _, ok := scopes[""]; ok {
			return nil, InvalidPolicyFormatError(fmt.Sprintf(`transport %q: the transport-wide "" scope may only be set in the base policy, not in a drop-in fragment`, transport))
		}
	}
	return map[string]PolicyTransportScopes(transports), nil
}

// loadPolicyWithDropIns reads the base policy and all drop-in fragments found by conf
// and returns the composed policy.
func loadPolicyWithDropIns(conf *configfile.File) (*Policy, []PolicyScopeSource, error) {
	paths, err := configfile.GetSearchPaths(conf)
	if err != nil {
		return nil, nil, err
	}

	var base *Policy
	var baseName string
	var fragments []policyFragment
	for item, err := range configfile.Read(conf) {
		if err != nil {
			return nil, nil, err
		}
		contents, err := io.ReadAll(item.Reader)
		if err != nil {
			return nil, nil, err
		}
		if base == nil && len(fragments) == 0 && slices.Contains(paths.MainFiles, item.Name) {
			base, err = NewPolicyFromBytes(contents)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid policy in %q: %w", item.Name, err)
			}
			baseName = item.Name
			continue
		}
		transports, err := newPolicyFragmentFromBytes(contents)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid policy fragment in %q: %w", item.Name, err)
		}
		fragments = append(fragments, policyFragment{name: item.Name, transports: transports})
	}

	if base == nil {
		if len(fragments) > 0 {
			return nil, nil, fmt.Errorf("found policy drop-in fragments (first: %q) but no base policy file in %v", fragments[0].name, paths.MainFiles)
		}
		return nil, nil, fmt.Errorf("no policy file found in %v: %w", paths.MainFiles, configfile.ErrConfigFileNotFound)
	}
	return mergePolicyFragments(base, baseName, fragments)
}

type policyScopeKey struct {
	transport string
	scope     string
}

func (k policyScopeKey) String() string { return k.transport + ":" + k.scope }

// mergePolicyFragments composes base with fragments according to the rules at the top of this file.
func mergePolicyFragments(base *Policy, baseName string, fragments []policyFragment) (*Policy, []PolicyScopeSource, error) {
	owner := map[policyScopeKey]string{}
	own := map[policyScopeKey]PolicyRequirements{}
	fromFragment := map[policyScopeKey]bool{}

	for transport, scopes := range base.Transports {
		for scope, reqs := range scopes {
			k := policyScopeKey{transport, scope}
			owner[k] = baseName
			own[k] = reqs
		}
	}
	for _, f := range fragments {
		for transport, scopes := range f.transports {
			for scope, reqs := range scopes {
				k := policyScopeKey{transport, scope}
				if prev, ok := owner[k]; ok {
					return nil, nil, fmt.Errorf("policy scope %q for transport %q is defined in both %q and %q; each scope may be defined by only one file", scope, transport, prev, f.name)
				}
				owner[k] = f.name
				own[k] = reqs
				fromFragment[k] = true
			}
		}
	}

	keys := make([]policyScopeKey, 0, len(own))
	for k := range own {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b policyScopeKey) int {
		return cmp.Or(cmp.Compare(a.transport, b.transport), cmp.Compare(a.scope, b.scope))
	})

	// parent returns the nearest enclosing explicit scope of k that is defined in a
	// different file than k ("" is never a parent).
	parent := func(k policyScopeKey) (policyScopeKey, bool) {
		var best policyScopeKey
		found := false
		for _, c := range keys {
			if c.transport != k.transport || c.scope == "" || c.scope == k.scope || owner[c] == owner[k] {
				continue
			}
			if scopeEncloses(c.scope, k.scope) && (!found || len(c.scope) > len(best.scope)) {
				best, found = c, true
			}
		}
		return best, found
	}

	type effective struct {
		reqs         PolicyRequirements
		alsoRequires []string
	}
	memo := map[policyScopeKey]effective{}
	var resolve func(k policyScopeKey) effective
	resolve = func(k policyScopeKey) effective {
		if e, ok := memo[k]; ok {
			return e
		}
		e := effective{reqs: slices.Clone(own[k])}
		if p, ok := parent(k); ok && k.scope != "" {
			pe := resolve(p)
			e.reqs = append(e.reqs, pe.reqs...)
			e.alsoRequires = append([]string{p.String()}, pe.alsoRequires...)
		}
		memo[k] = e
		return e
	}

	res := &Policy{Default: base.Default, Transports: map[string]PolicyTransportScopes{}}
	sources := make([]PolicyScopeSource, 0, len(keys))
	for _, k := range keys {
		e := resolve(k)
		if res.Transports[k.transport] == nil {
			res.Transports[k.transport] = PolicyTransportScopes{}
		}
		res.Transports[k.transport][k.scope] = e.reqs
		sources = append(sources, PolicyScopeSource{Transport: k.transport, Scope: k.scope, File: owner[k], AlsoRequires: e.alsoRequires})
		if fromFragment[k] || len(e.alsoRequires) > 0 { // only log scopes that differ from a plain single-file policy
			logrus.Debugf("Policy scope %s from %q, also requires %v", k, owner[k], e.alsoRequires)
		}
	}
	return res, sources, nil
}

// scopeEncloses reports whether the policy scope parent matches a superset of
// the images matched by child. PoC: implements docker/atomic-style scopes only
// (registry[/namespace...][/repo][:tag|@digest] and *.domain wildcards).
func scopeEncloses(parent, child string) bool {
	if strings.HasPrefix(child, parent) {
		rest := child[len(parent):]
		if rest != "" && (rest[0] == '/' || rest[0] == ':' || rest[0] == '@') {
			return true
		}
	}
	if suffix, ok := strings.CutPrefix(parent, "*"); ok { // "*.example.com"
		host, _, _ := strings.Cut(child, "/")
		return host != parent && strings.HasSuffix(host, suffix)
	}
	return false
}

// policyFilesConfig returns the configfile settings for policy.json with drop-ins enabled.
func policyFilesConfig(sys *types.SystemContext) *configfile.File {
	conf := &configfile.File{
		Name:            "policy",
		Extension:       "json",
		EnvironmentName: "CONTAINERS_POLICY_JSON",
		UserId:          unshare.GetRootlessUID(),
		ErrorIfNotFound: true,
	}
	if sys != nil {
		conf.RootForImplicitAbsolutePaths = sys.RootForImplicitAbsolutePaths
	}
	return conf
}

// DefaultPolicyWithSources is like DefaultPolicy, and also returns where each
// scope of the composed policy came from (for diagnostics).
func DefaultPolicyWithSources(sys *types.SystemContext) (*Policy, []PolicyScopeSource, error) {
	if sys != nil && sys.SignaturePolicyPath != "" {
		return NewPolicyFromFileWithDropInsAndSources(sys.SignaturePolicyPath, sys)
	}
	return loadPolicyWithDropIns(policyFilesConfig(sys))
}

// NewPolicyFromFileWithDropIns uses fileName as the base policy (instead of
// the default search path) and composes it with the system drop-in fragments.
// Unlike NewPolicyFromFile, which reads exactly one file.
func NewPolicyFromFileWithDropIns(fileName string, sys *types.SystemContext) (*Policy, error) {
	p, _, err := NewPolicyFromFileWithDropInsAndSources(fileName, sys)
	return p, err
}

// NewPolicyFromFileWithDropInsAndSources is NewPolicyFromFileWithDropIns plus provenance.
func NewPolicyFromFileWithDropInsAndSources(fileName string, sys *types.SystemContext) (*Policy, []PolicyScopeSource, error) {
	conf := policyFilesConfig(sys)
	conf.EnvironmentName = "" // an explicit path wins over CONTAINERS_POLICY_JSON{,_OVERRIDE}
	conf.CustomConfigFilePath = fileName
	return loadPolicyWithDropIns(conf)
}
