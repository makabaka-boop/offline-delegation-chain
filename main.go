package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

// Token is one signed edge in a delegation graph.
type Token struct {
	ID        string   `json:"id"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	Actions   []string `json:"actions"`
	Prefix    string   `json:"resource_prefix"`
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"`
	Remaining int      `json:"remaining_delegations"`
	Signature string   `json:"signature"`
}

// Request is the offline authorization input.
type Request struct {
	RootPublicKeys []string `json:"root_public_keys"`
	Tokens         []Token  `json:"tokens"`
	RevokedIDs     []string `json:"revoked_token_ids"`
	Query          struct {
		Principal string `json:"principal"`
		Action    string `json:"action"`
		Resource  string `json:"resource"`
		Time      int64  `json:"time"`
	} `json:"query"`
}

// NarrowingEvidence explains one parent-to-child delegation.
type NarrowingEvidence struct {
	ParentID string `json:"parent_id,omitempty"`
	ChildID  string `json:"child_id"`
	Actions  struct {
		Parent   []string `json:"parent"`
		Child    []string `json:"child"`
		Narrowed bool     `json:"narrowed"`
	} `json:"actions"`
	ResourcePrefix struct {
		Parent   string `json:"parent"`
		Child    string `json:"child"`
		Relation string `json:"relation"`
		Narrowed bool   `json:"narrowed"`
	} `json:"resource_prefix"`
	Validity struct {
		ParentNotBefore int64 `json:"parent_not_before"`
		ParentNotAfter  int64 `json:"parent_not_after"`
		ChildNotBefore  int64 `json:"child_not_before"`
		ChildNotAfter   int64 `json:"child_not_after"`
		Narrowed        bool  `json:"narrowed"`
	} `json:"validity"`
	RemainingDelegations struct {
		Parent    int  `json:"parent"`
		Child     int  `json:"child"`
		Decreased bool `json:"decreased"`
	} `json:"remaining_delegations"`
}

// Hop describes the first root token and every subsequent narrowing hop.
type Hop struct {
	TokenID           string             `json:"token_id"`
	Issuer            string             `json:"issuer"`
	Subject           string             `json:"subject"`
	Actions           []string           `json:"actions"`
	ResourcePrefix    string             `json:"resource_prefix"`
	NotBefore         int64              `json:"not_before"`
	NotAfter          int64              `json:"not_after"`
	Remaining         int                `json:"remaining_delegations"`
	NarrowingEvidence *NarrowingEvidence `json:"narrowing_evidence,omitempty"`
}

// Response is always JSON. authorized=false with reason is a policy result;
// malformed_input is an operational error and uses process exit code 2.
type Response struct {
	Authorized bool     `json:"authorized"`
	Principal  string   `json:"principal,omitempty"`
	Action     string   `json:"action,omitempty"`
	Resource   string   `json:"resource,omitempty"`
	Time       int64    `json:"time,omitempty"`
	TokenIDs   []string `json:"token_ids,omitempty"`
	Chain      []Hop    `json:"chain,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

func deny(reason string) Response {
	return Response{Authorized: false, Reason: reason}
}

func appendUint32Len(dst []byte, value []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(value)))
	dst = append(dst, n[:]...)
	return append(dst, value...)
}

func appendString(dst []byte, value string) []byte {
	return appendUint32Len(dst, []byte(value))
}

func appendInt64(dst []byte, value int64) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(value))
	return append(dst, n[:]...)
}

func appendInt(dst []byte, value int) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(value))
	return append(dst, n[:]...)
}

// canonicalToken returns the complete length-prefixed byte string covered by
// the Ed25519 signature. Key fields are their 32-byte Ed25519 values; this
// avoids two different base64 encodings representing the same signer. The ID
// is also signed, binding a revocation identifier to the token it revokes.
func canonicalToken(t Token) []byte {
	issuer, err := decodeKey(t.Issuer, "issuer")
	if err != nil {
		panic(err)
	}
	subject, err := decodeKey(t.Subject, "subject")
	if err != nil {
		panic(err)
	}

	var b []byte
	b = appendString(b, t.ID)
	b = appendUint32Len(b, issuer)
	b = appendUint32Len(b, subject)

	actions := append([]string(nil), t.Actions...)
	sort.Strings(actions)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(actions)))
	b = append(b, n[:]...)
	for _, action := range actions {
		b = appendString(b, action)
	}

	b = appendString(b, t.Prefix)
	b = appendInt64(b, t.NotBefore)
	b = appendInt64(b, t.NotAfter)
	b = appendInt(b, t.Remaining)
	return b
}

func decodeKey(value, field string) (ed25519.PublicKey, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%s is empty", field)
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not base64: %w", field, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s must be %d bytes", field, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func decodeSignature(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("signature is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("signature is not base64: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}
	return raw, nil
}

func validPath(path string) bool {
	if path == "" || path == "." || path == ".." || strings.Contains(path, "//") {
		return false
	}
	if path == "/" {
		return true
	}
	if strings.HasSuffix(path, "/") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// pathMatches applies the prefix rule only on path segment boundaries: /a/b
// covers /a/b and /a/b/c, but not /a/bb or /ab. Root "/" covers every path.
func pathMatches(prefix, resource string) bool {
	if prefix == "/" {
		return true
	}
	return prefix == resource || strings.HasPrefix(resource, prefix+"/")
}

type engine struct {
	roots      map[string]ed25519.PublicKey
	byID       map[string]Token
	revoked    map[string]bool
	children   map[string][]Token
	rootIDs    []string
	suffixBest map[string][]Token
}

type parsedToken struct {
	token   Token
	issuer  ed25519.PublicKey
	subject ed25519.PublicKey
}

func validate(req Request) (*engine, Response) {
	if len(req.RootPublicKeys) < 1 || len(req.RootPublicKeys) > 4 {
		return nil, deny("invalid_root_count")
	}
	if len(req.Tokens) > 40 {
		return nil, deny("too_many_tokens")
	}

	roots := make(map[string]ed25519.PublicKey, len(req.RootPublicKeys))
	for i, encoded := range req.RootPublicKeys {
		key, err := decodeKey(encoded, fmt.Sprintf("root_public_keys[%d]", i))
		if err != nil {
			return nil, deny("invalid_root_public_key")
		}
		roots[string(key)] = key
	}

	if len(req.Tokens) == 0 {
		return nil, deny("no_valid_chain")
	}

	parsed := make([]parsedToken, 0, len(req.Tokens))
	byID := make(map[string]Token, len(req.Tokens))

	// Collect and syntactically validate all tokens first. JSON token order is
	// not chain order, so issuer reachability and signatures are checked below.
	for _, token := range req.Tokens {
		if strings.TrimSpace(token.ID) == "" {
			return nil, deny("empty_token_id")
		}
		if _, exists := byID[token.ID]; exists {
			return nil, deny("duplicate_token_id")
		}

		issuerKey, err := decodeKey(token.Issuer, "issuer")
		if err != nil {
			return nil, deny("invalid_issuer_key")
		}
		subjectKey, err := decodeKey(token.Subject, "subject")
		if err != nil {
			return nil, deny("invalid_subject_key")
		}
		if bytes.Equal(issuerKey, subjectKey) {
			return nil, deny("delegation_cycle")
		}
		if token.NotBefore >= token.NotAfter {
			return nil, deny("invalid_validity_interval")
		}
		if token.Remaining < 0 || token.Remaining > (1<<32)-1 {
			return nil, deny("invalid_remaining_delegations")
		}
		if !validPath(token.Prefix) || !validPath(req.Query.Resource) {
			return nil, deny("invalid_resource_path")
		}
		if _, err := decodeSignature(token.Signature); err != nil {
			return nil, deny("invalid_signature_encoding")
		}
		seenActions := make(map[string]bool, len(token.Actions))
		for _, action := range token.Actions {
			if strings.TrimSpace(action) == "" {
				return nil, deny("empty_action")
			}
			if seenActions[action] {
				return nil, deny("duplicate_action")
			}
			seenActions[action] = true
		}

		byID[token.ID] = token
		parsed = append(parsed, parsedToken{token: token, issuer: issuerKey, subject: subjectKey})
	}

	if !allIssuersReachable(parsed, roots) {
		return nil, deny("unknown_issuer")
	}

	for _, entry := range parsed {
		signature, _ := decodeSignature(entry.token.Signature)
		if !ed25519.Verify(entry.issuer, canonicalToken(entry.token), signature) {
			return nil, deny("bad_signature")
		}
	}

	if len(req.RevokedIDs) > 40 {
		return nil, deny("too_many_revocations")
	}
	revoked := make(map[string]bool, len(req.RevokedIDs))
	for _, id := range req.RevokedIDs {
		if strings.TrimSpace(id) == "" {
			return nil, deny("empty_revocation_id")
		}
		revoked[id] = true
	}

	children := make(map[string][]Token)
	var rootsTokens []Token
	for _, entry := range parsed {
		if _, isRoot := roots[string(entry.issuer)]; isRoot {
			rootsTokens = append(rootsTokens, entry.token)
		} else {
			children[string(entry.issuer)] = append(children[string(entry.issuer)], entry.token)
		}
	}
	for id := range children {
		sort.Slice(children[id], func(i, j int) bool {
			return children[id][i].ID < children[id][j].ID
		})
	}
	sort.Slice(rootsTokens, func(i, j int) bool {
		return rootsTokens[i].ID < rootsTokens[j].ID
	})

	if hasCycle(parsed, roots) {
		return nil, deny("delegation_cycle")
	}

	rootIDs := make([]string, len(rootsTokens))
	for i, token := range rootsTokens {
		rootIDs[i] = token.ID
	}
	return &engine{
		roots:      roots,
		byID:       byID,
		revoked:    revoked,
		children:   children,
		rootIDs:    rootIDs,
		suffixBest: make(map[string][]Token),
	}, Response{}
}

func allIssuersReachable(tokens []parsedToken, roots map[string]ed25519.PublicKey) bool {
	adjacency := make(map[string][]string)
	issuers := make(map[string]bool)
	for _, entry := range tokens {
		from := string(entry.issuer)
		adjacency[from] = append(adjacency[from], string(entry.subject))
		issuers[from] = true
	}

	reachable := make(map[string]bool, len(roots))
	queue := make([]string, 0, len(roots))
	for root := range roots {
		if !reachable[root] {
			reachable[root] = true
			queue = append(queue, root)
		}
	}
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		for _, next := range adjacency[key] {
			if !reachable[next] {
				reachable[next] = true
				queue = append(queue, next)
			}
		}
	}
	for issuer := range issuers {
		if !reachable[issuer] {
			return false
		}
	}
	return true
}

// hasCycle detects a cycle in the identity graph (issuer -> subject). A ring
// is rejected even if one or more of its tokens is revoked: revocation excludes
// an edge from a valid chain, but it cannot repair a malformed batch.
func hasCycle(tokens []parsedToken, roots map[string]ed25519.PublicKey) bool {
	adjacency := make(map[string][]string)
	for _, entry := range tokens {
		from := string(entry.issuer)
		to := string(entry.subject)
		adjacency[from] = append(adjacency[from], to)
	}

	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int)
	var visit func(key string) bool
	visit = func(key string) bool {
		switch color[key] {
		case gray:
			return true
		case black:
			return false
		}
		color[key] = gray
		for _, next := range adjacency[key] {
			if visit(next) {
				return true
			}
		}
		color[key] = black
		return false
	}

	// Roots anchor normal chains. Visiting all known issuers also rejects rings
	// or loops that are disconnected from every trust root.
	starting := make([]string, 0, len(roots)+len(adjacency))
	for root := range roots {
		starting = append(starting, root)
	}
	for issuer := range adjacency {
		starting = append(starting, issuer)
	}
	sort.Strings(starting)
	for _, key := range starting {
		if visit(key) {
			return true
		}
	}
	return false
}

func actionsContain(actions []string, action string) bool {
	for _, candidate := range actions {
		if candidate == action {
			return true
		}
	}
	return false
}

func sortedActions(actions []string) []string {
	out := append([]string(nil), actions...)
	sort.Strings(out)
	return out
}

func rootEligible(parent Token, action, resource string, at int64) bool {
	return at >= parent.NotBefore && at < parent.NotAfter &&
		pathMatches(parent.Prefix, resource) &&
		actionsContain(parent.Actions, action)
}

func childEligible(parent, child Token, action, resource string, at int64) bool {
	if child.NotBefore < parent.NotBefore || child.NotAfter > parent.NotAfter {
		return false
	}
	if !(at >= child.NotBefore && at < child.NotAfter) {
		return false
	}
	if child.Prefix != parent.Prefix && !pathMatches(parent.Prefix, child.Prefix) {
		return false
	}
	if !pathMatches(child.Prefix, resource) {
		return false
	}
	for _, childAction := range child.Actions {
		if !actionsContain(parent.Actions, childAction) {
			return false
		}
	}
	if !actionsContain(child.Actions, action) {
		return false
	}
	if child.Remaining >= parent.Remaining {
		return false
	}
	return true
}

// bestSuffix returns the lexicographically smallest valid suffix beginning
// after parent and ending at principal. Outgoing edges are sorted by child ID,
// so the first complete DFS suffix is the lexicographically smallest one.
// Memoization keeps the bounded 40-token graph traversal linear.
func bestSuffix(parent Token, e *engine, principal ed25519.PublicKey, action, resource string, at int64) []Token {
	if suffix, cached := e.suffixBest[parent.ID]; cached {
		return suffix
	}

	parentSubject, _ := decodeKey(parent.Subject, "subject")
	var best []Token
	for _, child := range e.children[string(parentSubject)] {
		if e.revoked[child.ID] || !childEligible(parent, child, action, resource, at) {
			continue
		}
		childSubject, _ := decodeKey(child.Subject, "subject")
		if bytes.Equal(childSubject, principal) {
			best = []Token{child}
			break
		}
		if child.Remaining == 0 {
			continue
		}
		if suffix := bestSuffix(child, e, principal, action, resource, at); suffix != nil {
			best = append([]Token{child}, suffix...)
			break
		}
	}
	e.suffixBest[parent.ID] = best
	return best
}

func pathRelation(parent, child string) string {
	if parent == child {
		return "equal"
	}
	return "descendant"
}

func makeHop(token Token, parent *Token) Hop {
	hop := Hop{
		TokenID:        token.ID,
		Issuer:         token.Issuer,
		Subject:        token.Subject,
		Actions:        sortedActions(token.Actions),
		ResourcePrefix: token.Prefix,
		NotBefore:      token.NotBefore,
		NotAfter:       token.NotAfter,
		Remaining:      token.Remaining,
	}
	if parent != nil {
		evidence := &NarrowingEvidence{ParentID: parent.ID, ChildID: token.ID}
		evidence.Actions.Parent = sortedActions(parent.Actions)
		evidence.Actions.Child = hop.Actions
		evidence.Actions.Narrowed = !reflect.DeepEqual(evidence.Actions.Parent, evidence.Actions.Child)
		evidence.ResourcePrefix.Parent = parent.Prefix
		evidence.ResourcePrefix.Child = token.Prefix
		evidence.ResourcePrefix.Relation = pathRelation(parent.Prefix, token.Prefix)
		evidence.ResourcePrefix.Narrowed = parent.Prefix != token.Prefix
		evidence.Validity.ParentNotBefore = parent.NotBefore
		evidence.Validity.ParentNotAfter = parent.NotAfter
		evidence.Validity.ChildNotBefore = token.NotBefore
		evidence.Validity.ChildNotAfter = token.NotAfter
		evidence.Validity.Narrowed = token.NotBefore > parent.NotBefore || token.NotAfter < parent.NotAfter
		evidence.RemainingDelegations.Parent = parent.Remaining
		evidence.RemainingDelegations.Child = token.Remaining
		evidence.RemainingDelegations.Decreased = token.Remaining < parent.Remaining
		hop.NarrowingEvidence = evidence
	}
	return hop
}

func authorize(req Request) Response {
	e, invalid := validate(req)
	if invalid.Reason != "" {
		return invalid
	}

	principal, err := decodeKey(req.Query.Principal, "query.principal")
	if err != nil {
		return deny("invalid_principal")
	}
	if strings.TrimSpace(req.Query.Action) == "" {
		return deny("empty_action")
	}
	if !validPath(req.Query.Resource) {
		return deny("invalid_resource_path")
	}

	var best []Token
	for _, rootID := range e.rootIDs {
		root := e.byID[rootID]
		if e.revoked[root.ID] || !rootEligible(root, req.Query.Action, req.Query.Resource, req.Query.Time) {
			continue
		}

		chain := []Token{root}
		subject, _ := decodeKey(root.Subject, "subject")
		if bytes.Equal(subject, principal) {
			if lexLess(chain, best) {
				best = chain
			}
			continue
		}
		if root.Remaining == 0 {
			continue
		}
		if suffix := bestSuffix(root, e, principal, req.Query.Action, req.Query.Resource, req.Query.Time); suffix != nil {
			candidate := append(chain, suffix...)
			if lexLess(candidate, best) {
				best = candidate
			}
		}
	}

	if best == nil {
		return deny("unauthorized")
	}

	ids := make([]string, len(best))
	hops := make([]Hop, len(best))
	for i, token := range best {
		ids[i] = token.ID
		var parent *Token
		if i > 0 {
			parent = &best[i-1]
		}
		hops[i] = makeHop(token, parent)
	}
	return Response{
		Authorized: true,
		Principal:  req.Query.Principal,
		Action:     req.Query.Action,
		Resource:   req.Query.Resource,
		Time:       req.Query.Time,
		TokenIDs:   ids,
		Chain:      hops,
	}
}

func lexLess(a, b []Token) bool {
	if b == nil {
		return true
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i].ID != b[i].ID {
			return a[i].ID < b[i].ID
		}
	}
	return len(a) < len(b)
}

func run(args []string, stdin io.Reader) Response {
	var input []byte
	var err error
	if len(args) == 0 || args[0] == "-" {
		input, err = io.ReadAll(stdin)
	} else if len(args) != 1 {
		err = errors.New("usage: delegauth [request.json|-]")
	} else {
		input, err = os.ReadFile(args[0])
	}
	if err != nil {
		return deny("malformed_input: " + err.Error())
	}

	var req Request
	if err := json.Unmarshal(input, &req); err != nil {
		return deny("malformed_input: " + err.Error())
	}
	return authorize(req)
}

func main() {
	response := run(os.Args[1:], os.Stdin)
	encoded, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(string(encoded))
	if !response.Authorized {
		if strings.HasPrefix(response.Reason, "malformed_input:") {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
