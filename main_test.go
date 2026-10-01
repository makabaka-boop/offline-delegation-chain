package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

type keyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func generateKey(t *testing.T) keyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{pub: pub, priv: priv}
}

func keyString(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key)
}

func signToken(t *testing.T, token Token, issuer ed25519.PrivateKey) Token {
	t.Helper()
	token.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(issuer, canonicalToken(token)))
	return token
}

func unsignedToken(id string, issuer, subject keyPair, actions []string, prefix string, nb, na int64, remaining int) Token {
	return Token{
		ID:        id,
		Issuer:    keyString(issuer.pub),
		Subject:   keyString(subject.pub),
		Actions:   actions,
		Prefix:    prefix,
		NotBefore: nb,
		NotAfter:  na,
		Remaining: remaining,
	}
}

func makeRequest(t *testing.T, roots []keyPair, tokens []Token, revoked []string, principal keyPair, action, resource string, at int64) Request {
	t.Helper()
	req := Request{Tokens: tokens, RevokedIDs: revoked}
	for _, root := range roots {
		req.RootPublicKeys = append(req.RootPublicKeys, keyString(root.pub))
	}
	req.Query.Principal = keyString(principal.pub)
	req.Query.Action = action
	req.Query.Resource = resource
	req.Query.Time = at
	return req
}

func assertUnauthorized(t *testing.T, req Request, wantReason string) {
	t.Helper()
	got := authorize(req)
	if got.Authorized {
		t.Fatalf("expected unauthorized, got chain %v", got.TokenIDs)
	}
	if got.Reason != wantReason {
		t.Fatalf("reason = %q, want %q", got.Reason, wantReason)
	}
}

func assertIDs(t *testing.T, req Request, want []string) {
	t.Helper()
	got := authorize(req)
	if !got.Authorized {
		t.Fatalf("expected authorized: %s", got.Reason)
	}
	if !reflect.DeepEqual(got.TokenIDs, want) {
		t.Fatalf("chain = %v, want %v", got.TokenIDs, want)
	}
}

func cloneTokens(t *testing.T, tokens []Token) []Token {
	t.Helper()
	encoded, err := json.Marshal(tokens)
	if err != nil {
		t.Fatal(err)
	}
	var out []Token
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestValidChainAndNarrowingEvidence(t *testing.T) {
	root := generateKey(t)
	alice := generateKey(t)
	bob := generateKey(t)

	r1 := signToken(t, unsignedToken("r1", root, alice, []string{"read", "write"}, "/org/app", 10, 30, 2), root.priv)
	a1 := signToken(t, unsignedToken("a1", alice, bob, []string{"read"}, "/org/app/data", 12, 28, 1), alice.priv)

	req := makeRequest(t, []keyPair{root}, []Token{r1, a1}, nil, bob, "read", "/org/app/data/file", 20)
	got := authorize(req)
	if !got.Authorized {
		t.Fatalf("expected authorized: %s", got.Reason)
	}
	if want := []string{"r1", "a1"}; !reflect.DeepEqual(got.TokenIDs, want) {
		t.Fatalf("ids = %v, want %v", got.TokenIDs, want)
	}
	if len(got.Chain) != 2 || got.Chain[0].NarrowingEvidence != nil {
		t.Fatalf("unexpected chain evidence: %+v", got.Chain)
	}
	evidence := got.Chain[1].NarrowingEvidence
	if evidence == nil {
		t.Fatal("missing child narrowing evidence")
	}
	if evidence.ResourcePrefix.Relation != "descendant" ||
		evidence.ResourcePrefix.Parent != "/org/app" ||
		evidence.ResourcePrefix.Child != "/org/app/data" {
		t.Fatalf("bad prefix evidence: %+v", evidence.ResourcePrefix)
	}
	if evidence.Validity.ParentNotBefore != 10 || evidence.Validity.ChildNotBefore != 12 ||
		evidence.Validity.ParentNotAfter != 30 || evidence.Validity.ChildNotAfter != 28 {
		t.Fatalf("bad time evidence: %+v", evidence.Validity)
	}
	if evidence.RemainingDelegations.Parent != 2 || evidence.RemainingDelegations.Child != 1 {
		t.Fatalf("bad depth evidence: %+v", evidence.RemainingDelegations)
	}
}

func TestBoundaryTimes(t *testing.T) {
	root := generateKey(t)
	principal := generateKey(t)
	r1 := signToken(t, unsignedToken("r1", root, principal, []string{"read"}, "/x", 10, 20, 1), root.priv)

	base := makeRequest(t, []keyPair{root}, []Token{r1}, nil, principal, "read", "/x/y", 10)
	assertIDs(t, base, []string{"r1"})

	atStart := base
	atStart.Query.Time = 10
	assertIDs(t, atStart, []string{"r1"})

	beforeStart := base
	beforeStart.Query.Time = 9
	assertUnauthorized(t, beforeStart, "unauthorized")

	atEnd := base
	atEnd.Query.Time = 20
	assertUnauthorized(t, atEnd, "unauthorized")
}

func TestSegmentPathPrefix(t *testing.T) {
	root := generateKey(t)
	principal := generateKey(t)
	r1 := signToken(t, unsignedToken("r1", root, principal, []string{"read"}, "/app/data", 0, 100, 1), root.priv)

	cases := []struct {
		resource string
		allowed  bool
	}{
		{"/app/data", true},
		{"/app/data/file", true},
		{"/app/database", false},
		{"/app/data2", false},
		{"/other", false},
	}
	for _, tc := range cases {
		req := makeRequest(t, []keyPair{root}, []Token{r1}, nil, principal, "read", tc.resource, 50)
		response := authorize(req)
		if response.Authorized != tc.allowed {
			t.Fatalf("resource %s authorized=%v, want %v (%s)", tc.resource, response.Authorized, tc.allowed, response.Reason)
		}
	}
}

func TestRootPrefixAndChildBoundaryTimes(t *testing.T) {
	root := generateKey(t)
	alice := generateKey(t)
	principal := generateKey(t)
	rootToken := signToken(t, unsignedToken("r1", root, alice, []string{"read"}, "/", 10, 30, 2), root.priv)
	child := signToken(t, unsignedToken("a1", alice, principal, []string{"read"}, "/x", 20, 30, 1), alice.priv)

	for _, at := range []int64{20, 29} {
		req := makeRequest(t, []keyPair{root}, []Token{rootToken, child}, nil, principal, "read", "/x/y", at)
		assertIDs(t, req, []string{"r1", "a1"})
	}

	for _, at := range []int64{19, 30} {
		req := makeRequest(t, []keyPair{root}, []Token{rootToken, child}, nil, principal, "read", "/x/y", at)
		assertUnauthorized(t, req, "unauthorized")
	}
}

func TestTamperedSignedPayloadRejected(t *testing.T) {
	root := generateKey(t)
	alice := generateKey(t)
	principal := generateKey(t)

	original := signToken(t, unsignedToken("r1", root, alice, []string{"read"}, "/a", 0, 100, 2), root.priv)
	child := signToken(t, unsignedToken("a1", alice, principal, []string{"read"}, "/a/b", 0, 100, 1), alice.priv)

	mutated := cloneTokens(t, []Token{original})[0]
	mutated.Actions = []string{"read", "write"}
	req := makeRequest(t, []keyPair{root}, []Token{mutated, child}, nil, principal, "read", "/a/b", 50)
	assertUnauthorized(t, req, "bad_signature")
}

func TestMidChainRevocationAndFallbackChain(t *testing.T) {
	root := generateKey(t)
	otherRoot := generateKey(t)
	alice := generateKey(t)
	otherAlice := generateKey(t)
	principal := generateKey(t)

	firstRoot := signToken(t, unsignedToken("r-z", root, alice, []string{"read"}, "/r", 0, 100, 2), root.priv)
	firstMid := signToken(t, unsignedToken("m-z", alice, principal, []string{"read"}, "/r/p", 0, 100, 1), alice.priv)

	secondRoot := signToken(t, unsignedToken("r-a", otherRoot, otherAlice, []string{"read"}, "/r", 0, 100, 2), otherRoot.priv)
	secondMid := signToken(t, unsignedToken("m-a", otherAlice, principal, []string{"read"}, "/r/p", 0, 100, 1), otherAlice.priv)

	tokens := []Token{firstRoot, firstMid, secondRoot, secondMid}
	roots := []keyPair{root, otherRoot}
	base := makeRequest(t, roots, tokens, nil, principal, "read", "/r/p/x", 50)
	assertIDs(t, base, []string{"r-a", "m-a"})

	revokedMid := base
	revokedMid.RevokedIDs = []string{"m-a"}
	assertIDs(t, revokedMid, []string{"r-z", "m-z"})

	revokedRoot := revokedMid
	revokedRoot.RevokedIDs = []string{"m-a", "r-z"}
	assertUnauthorized(t, revokedRoot, "unauthorized")
}

func TestLexicographicallySmallestChainExploresDeadEnds(t *testing.T) {
	root := generateKey(t)
	first := generateKey(t)
	second := generateKey(t)
	principal := generateKey(t)

	rootToken := signToken(t, unsignedToken("r1", root, first, []string{"read"}, "/x", 0, 100, 3), root.priv)
	// A lexicographically smaller edge leads to a subject that cannot finish.
	deadEnd := signToken(t, unsignedToken("aa", first, second, []string{"read"}, "/x", 0, 100, 0), first.priv)
	goodChild := signToken(t, unsignedToken("ab", first, principal, []string{"read"}, "/x", 0, 100, 2), first.priv)

	req := makeRequest(t, []keyPair{root}, []Token{rootToken, deadEnd, goodChild}, nil, principal, "read", "/x/y", 50)
	assertIDs(t, req, []string{"r1", "ab"})
}

func TestChildCannotBroadenDelegation(t *testing.T) {
	root := generateKey(t)
	alice := generateKey(t)
	principal := generateKey(t)
	r1 := signToken(t, unsignedToken("r1", root, alice, []string{"read"}, "/parent", 10, 20, 2), root.priv)

	cases := map[string]Token{
		"action": signToken(t, unsignedToken("c1", alice, principal, []string{"write"}, "/parent", 10, 20, 1), alice.priv),
		"path":   signToken(t, unsignedToken("c1", alice, principal, []string{"read"}, "/other", 10, 20, 1), alice.priv),
		"time":   signToken(t, unsignedToken("c1", alice, principal, []string{"read"}, "/parent", 9, 20, 1), alice.priv),
		"depth":  signToken(t, unsignedToken("c1", alice, principal, []string{"read"}, "/parent", 10, 20, 2), alice.priv),
	}
	for name, child := range cases {
		t.Run(name, func(t *testing.T) {
			req := makeRequest(t, []keyPair{root}, []Token{r1, child}, nil, principal, "read", "/parent", 15)
			if name == "action" {
				req.Query.Action = "write"
			}
			assertUnauthorized(t, req, "unauthorized")
		})
	}
}

func TestBatchRejections(t *testing.T) {
	root := generateKey(t)
	alice := generateKey(t)
	bob := generateKey(t)
	r1 := signToken(t, unsignedToken("r1", root, alice, []string{"read"}, "/x", 0, 100, 1), root.priv)
	validChild := signToken(t, unsignedToken("a1", alice, bob, []string{"read"}, "/x", 0, 100, 0), alice.priv)
	base := makeRequest(t, []keyPair{root}, []Token{r1, validChild}, nil, bob, "read", "/x", 50)

	t.Run("duplicate ID", func(t *testing.T) {
		req := base
		duplicate := cloneTokens(t, req.Tokens)
		duplicate[1].ID = "r1"
		duplicate[1] = signToken(t, duplicate[1], alice.priv)
		req.Tokens = duplicate
		assertUnauthorized(t, req, "duplicate_token_id")
	})

	t.Run("unknown issuer", func(t *testing.T) {
		unknown := generateKey(t)
		bad := signToken(t, unsignedToken("x1", unknown, bob, []string{"read"}, "/x", 0, 100, 0), unknown.priv)
		req := base
		req.Tokens = append(cloneTokens(t, req.Tokens), bad)
		req.Query.Principal = keyString(bob.pub)
		assertUnauthorized(t, req, "unknown_issuer")
	})

	t.Run("bad signature rejects whole batch", func(t *testing.T) {
		badRoot := generateKey(t)
		badSubject := generateKey(t)
		bad := signToken(t, unsignedToken("bad", badRoot, badSubject, []string{"read"}, "/x", 0, 100, 0), badRoot.priv)
		bad.Prefix = "/y" // signature still covers /x
		req := base
		req.RootPublicKeys = append(append([]string(nil), req.RootPublicKeys...), keyString(badRoot.pub))
		req.Tokens = append(cloneTokens(t, req.Tokens), bad)
		assertUnauthorized(t, req, "bad_signature")
	})

	t.Run("identity cycle", func(t *testing.T) {
		a := generateKey(t)
		b := generateKey(t)
		c := generateKey(t)
		cycleRoot := signToken(t, unsignedToken("cr", root, a, []string{"read"}, "/x", 0, 100, 3), root.priv)
		edge1 := signToken(t, unsignedToken("c1", a, b, []string{"read"}, "/x", 0, 100, 2), a.priv)
		edge2 := signToken(t, unsignedToken("c2", b, c, []string{"read"}, "/x", 0, 100, 1), b.priv)
		edge3 := signToken(t, unsignedToken("c3", c, a, []string{"read"}, "/x", 0, 100, 0), c.priv)
		req := makeRequest(t, []keyPair{root}, []Token{cycleRoot, edge1, edge2, edge3}, nil, c, "read", "/x", 50)
		assertUnauthorized(t, req, "delegation_cycle")
	})
}

func TestLimits(t *testing.T) {
	root := generateKey(t)
	principal := generateKey(t)
	token := signToken(t, unsignedToken("r1", root, principal, []string{"read"}, "/x", 0, 100, 1), root.priv)

	t.Run("five roots", func(t *testing.T) {
		roots := []keyPair{root, generateKey(t), generateKey(t), generateKey(t), generateKey(t)}
		req := makeRequest(t, roots, []Token{token}, nil, principal, "read", "/x", 50)
		assertUnauthorized(t, req, "invalid_root_count")
	})

	t.Run("41 tokens", func(t *testing.T) {
		issuer := generateKey(t)
		subject := generateKey(t)
		tokens := make([]Token, 41)
		for i := range tokens {
			id := fmt.Sprintf("token-%02d", i)
			tokens[i] = signToken(t, unsignedToken(id, issuer, subject, []string{"read"}, "/x", 0, 100, 0), issuer.priv)
		}
		req := makeRequest(t, []keyPair{root}, tokens, nil, principal, "read", "/x", 50)
		assertUnauthorized(t, req, "too_many_tokens")
	})
}

func TestCommandLineJSON(t *testing.T) {
	root := generateKey(t)
	principal := generateKey(t)
	r1 := signToken(t, unsignedToken("r1", root, principal, []string{"read"}, "/x", 0, 100, 1), root.priv)
	req := makeRequest(t, []keyPair{root}, []Token{r1}, nil, principal, "read", "/x/y", 50)
	input, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}

	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go executable not found in PATH")
	}
	cmd := exec.Command(goBinary, "run", ".", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, output)
	}
	var response Response
	if err := json.Unmarshal(output, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Authorized {
		t.Fatalf("CLI denied request: %s", response.Reason)
	}
}
