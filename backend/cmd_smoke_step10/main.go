// Step 10 smoke test.
//
// Exercises the 6 sub-tests from the Step 10 spec:
//
//  1. Add contact → accept → verify status='accepted' in DB
//  2. Block contact → verify status='blocked'
//  3. Create group → invite member → verify group_members row
//  4. Leave group → verify member removed
//  5. Owner leaves 2-person group → ownership transferred
//  6. Last member leaves → group deleted (CASCADE)
//
// Run from inside the iceq-net network with the same
// ICEQ_JWT_SECRET as the auth-service / message-service:
//
//	docker run --rm --network iceq-net \
//	  -v /path/to/iceq:/src \
//	  -w /src/backend -e ICEQ_JWT_SECRET=dev-secret-not-for-prod \
//	  golang:1.25-alpine sh -c "go run ./cmd_smoke_step10"
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/iceq/iceq/shared/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	authsvcBase  = "http://auth-service:8080"
	msgsvcBase   = "http://message-service:8080"
	defaultPGDSN = "postgres://postgres:postgres@postgres:5432/iceq?sslmode=disable"
	// F-2 (JWT assessment): bumped to 38 bytes to clear the
	// 32-byte minSecretBytes floor and to avoid being a
	// substring of any of the knownWeakSecrets entries.
	jwtSecret = "step10-smoketest-secret-not-for-prod-32"

	// Test users. UINs in the 9xxxxxx range are reserved
	// for smoke tests to avoid colliding with real
	// users (which start at 10,000,000 via the
	// uin_seq sequence).
	aliceUIN int64 = 9999010
	bobUIN   int64 = 9999011
	carolUIN int64 = 9999012
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Open the pg pool BEFORE constructing the JWT Manager
	// (F-5: NewManager now requires a *pgxpool.Pool for the
	// session_epoch check in Verify).
	pool, err := pgxpool.New(ctx, pgDSNFromEnv())
	if err != nil {
		fail("connect pg: %v", err)
	}
	defer pool.Close()

	mgr := newJWTManager(pool)
	aliceTok := mintAccessToken(mgr, aliceUIN)
	bobTok := mintAccessToken(mgr, bobUIN)
	// carolTok is reserved for tests that need a third
	// party (e.g. "Carol accepts a request from Bob").
	// Step 10's six sub-tests only need Alice and Bob,
	// but the constant is here so future tests can use
	// it without re-plumbing.
	_ = mintAccessToken(mgr, carolUIN)

	// Ensure the three test users exist. The contact /
	// group tables have FKs into users, so we need
	// real rows. We use the panic-wipe-friendly
	// pattern: an UPSERT that sets identity_key and
	// username if the row already exists.
	for _, u := range []int64{aliceUIN, bobUIN, carolUIN} {
		_, err := pool.Exec(ctx,
			`INSERT INTO users (uin, username, password_hash, identity_key)
			 VALUES ($1, $2, '', '')
			 ON CONFLICT (uin) DO NOTHING`,
			u, fmt.Sprintf("smoke_step10_%d", u))
		if err != nil {
			fail("seed user %d: %v", u, err)
		}
	}
	// Clean any prior contact / group state for these
	// UINs so the test is idempotent across runs.
	_, _ = pool.Exec(ctx, `DELETE FROM group_members WHERE uin = ANY($1)`, []int64{aliceUIN, bobUIN, carolUIN})
	_, _ = pool.Exec(ctx, `DELETE FROM groups WHERE owner_uin = ANY($1)`, []int64{aliceUIN, bobUIN, carolUIN})
	_, _ = pool.Exec(ctx, `DELETE FROM contacts WHERE owner_uin = ANY($1) OR target_uin = ANY($1)`, []int64{aliceUIN, bobUIN, carolUIN})

	pass, total := 0, 0
	check := func(name string, ok bool, info ...string) {
		total++
		if ok {
			fmt.Printf("  ✓ %s\n", name)
			pass++
		} else {
			extra := ""
			if len(info) > 0 {
				extra = "   " + info[0]
			}
			fmt.Printf("  ✗ %s%s\n", name, extra)
		}
	}

	// ---- 1. Add contact → accept → status='accepted' ----
	fmt.Println("\n=== 1. Add contact → accept → status='accepted' ===")
	// Alice adds Bob.
	status := postContact(ctx, aliceTok, bobUIN)
	check("POST /api/contacts returns 201 pending", status == http.StatusCreated, fmt.Sprintf("got %d", status))
	// Bob sees the pending request in his list.
	bobsList := listContacts(ctx, bobTok)
	check("Bob's list shows Alice as pending", containsStatus(bobsList, aliceUIN, "pending"))
	// Bob accepts.
	status = putAccept(ctx, bobTok, aliceUIN)
	check("PUT /api/contacts/{alice}/accept returns 200", status == http.StatusOK, fmt.Sprintf("got %d", status))
	// Both rows should be 'accepted' now.
	check("DB: contacts(alice, bob) = accepted", dbContactStatus(ctx, pool, aliceUIN, bobUIN) == "accepted")
	check("DB: contacts(bob, alice) = accepted", dbContactStatus(ctx, pool, bobUIN, aliceUIN) == "accepted")

	// ---- 2. Block contact → status='blocked' ----
	fmt.Println("\n=== 2. Block contact → status='blocked' ===")
	// Alice adds Carol.
	status = postContact(ctx, aliceTok, carolUIN)
	check("POST /api/contacts (carol) returns 201", status == http.StatusCreated, fmt.Sprintf("got %d", status))
	// Alice blocks Carol. Block works on any edge, not
	// just pending — let's use the pending row.
	status = putBlock(ctx, aliceTok, carolUIN)
	check("PUT /api/contacts/{carol}/block returns 200", status == http.StatusOK, fmt.Sprintf("got %d", status))
	check("DB: contacts(alice, carol) = blocked", dbContactStatus(ctx, pool, aliceUIN, carolUIN) == "blocked")
	// The reverse edge is intentionally untouched.
	check("DB: contacts(carol, alice) = pending (unchanged)", dbContactStatus(ctx, pool, carolUIN, aliceUIN) == "pending")

	// ---- 3. Create group → invite member → verify group_members row ----
	fmt.Println("\n=== 3. Create group → invite member ===")
	// Alice creates a group; she's the only member.
	g := createGroup(ctx, aliceTok, "smoke-test-group-1")
	check("POST /api/groups returns 201 with group_id", g.GroupID != "", "")
	check("Returned member_count = 1", g.MemberCount == 1, fmt.Sprintf("got %d", g.MemberCount))
	// Alice invites Bob.
	status = postGroupMember(ctx, aliceTok, g.GroupID, bobUIN)
	check("POST /api/groups/{id}/members returns 201", status == http.StatusCreated, fmt.Sprintf("got %d", status))
	// group_members has (group_id, alice) and (group_id, bob).
	check("DB: alice is a member of the group", dbGroupMember(ctx, pool, g.GroupID, aliceUIN) == "admin")
	check("DB: bob is a member of the group", dbGroupMember(ctx, pool, g.GroupID, bobUIN) == "member")
	check("DB: owner_uin = alice", dbGroupOwner(ctx, pool, g.GroupID) == aliceUIN)

	// ---- 4. Leave group → verify member removed ----
	fmt.Println("\n=== 4. Bob leaves the group ===")
	status = deleteGroupMember(ctx, bobTok, g.GroupID, bobUIN)
	check("DELETE /api/groups/{id}/members/bob returns 204", status == http.StatusNoContent, fmt.Sprintf("got %d", status))
	check("DB: bob is no longer a member", !dbGroupMemberExists(ctx, pool, g.GroupID, bobUIN))
	check("DB: alice is still a member", dbGroupMember(ctx, pool, g.GroupID, aliceUIN) == "admin")
	check("DB: group still exists", dbGroupExists(ctx, pool, g.GroupID))

	// ---- 5. Owner leaves 2-person group → ownership transferred ----
	fmt.Println("\n=== 5. Owner leaves 2-person group → ownership transferred ===")
	// Re-create the group with Alice as owner + Bob as
	// member, so the next assertion has a known starting
	// state.
	_, _ = pool.Exec(ctx, `DELETE FROM group_members WHERE group_id = $1`, g.GroupID)
	_, _ = pool.Exec(ctx, `DELETE FROM groups WHERE id = $1`, g.GroupID)
	g2 := createGroup(ctx, aliceTok, "smoke-test-transfer")
	status = postGroupMember(ctx, aliceTok, g2.GroupID, bobUIN)
	check("Group 2: bob invited", status == http.StatusCreated, fmt.Sprintf("got %d", status))
	check("Group 2: owner=alice pre-leave", dbGroupOwner(ctx, pool, g2.GroupID) == aliceUIN)
	// Alice (the owner) leaves. Bob is the only
	// remaining member → Bob inherits.
	status = deleteGroupMember(ctx, aliceTok, g2.GroupID, aliceUIN)
	check("DELETE alice's membership returns 204", status == http.StatusNoContent, fmt.Sprintf("got %d", status))
	check("Group 2: ownership transferred to bob", dbGroupOwner(ctx, pool, g2.GroupID) == bobUIN)
	check("Group 2: group still exists", dbGroupExists(ctx, pool, g2.GroupID))

	// ---- 6. Last member leaves → group deleted (CASCADE) ----
	fmt.Println("\n=== 6. Last member leaves → group deleted (CASCADE) ===")
	status = deleteGroupMember(ctx, bobTok, g2.GroupID, bobUIN)
	check("DELETE bob's membership returns 204", status == http.StatusNoContent, fmt.Sprintf("got %d", status))
	check("Group 2: group is now deleted", !dbGroupExists(ctx, pool, g2.GroupID))

	// ---- Summary ----
	fmt.Printf("\n=== %d/%d passed ===\n", pass, total)
	if pass != total {
		os.Exit(1)
	}
}

// =============================================================================
// HTTP helpers. Each returns either the parsed body or
// the HTTP status code (when the test cares about the
// status and not the body).
// =============================================================================

func postContact(ctx context.Context, tok string, target int64) int {
	req, _ := http.NewRequestWithContext(ctx, "POST", authsvcBase+"/api/contacts/", jsonBody(map[string]any{"target_uin": target}))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("postContact: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func putAccept(ctx context.Context, tok string, target int64) int {
	req, _ := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/api/contacts/%d/accept", authsvcBase, target), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("putAccept: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func putBlock(ctx context.Context, tok string, target int64) int {
	req, _ := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/api/contacts/%d/block", authsvcBase, target), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("putBlock: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

type listResp struct {
	Contacts []struct {
		UIN    int64  `json:"uin"`
		Status string `json:"status"`
	} `json:"contacts"`
}

func listContacts(ctx context.Context, tok string) listResp {
	req, _ := http.NewRequestWithContext(ctx, "GET", authsvcBase+"/api/contacts/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("listContacts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return listResp{}
	}
	var out listResp
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func containsStatus(l listResp, uin int64, status string) bool {
	for _, c := range l.Contacts {
		if c.UIN == uin && c.Status == status {
			return true
		}
	}
	return false
}

type groupResp struct {
	GroupID     string `json:"group_id"`
	Name        string `json:"name"`
	OwnerUIN    int64  `json:"owner_uin"`
	MemberCount int    `json:"member_count"`
}

func createGroup(ctx context.Context, tok, name string) groupResp {
	req, _ := http.NewRequestWithContext(ctx, "POST", msgsvcBase+"/api/groups/", jsonBody(map[string]any{"name": name}))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("createGroup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		fail("createGroup status %d: %s", resp.StatusCode, string(body))
	}
	var g groupResp
	_ = json.NewDecoder(resp.Body).Decode(&g)
	return g
}

func postGroupMember(ctx context.Context, tok, groupID string, uin int64) int {
	req, _ := http.NewRequestWithContext(ctx, "POST", msgsvcBase+"/api/groups/"+groupID+"/members", jsonBody(map[string]any{"uin": uin}))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("postGroupMember: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func deleteGroupMember(ctx context.Context, tok, groupID string, uin int64) int {
	req, _ := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/api/groups/%s/members/%d", msgsvcBase, groupID, uin), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("deleteGroupMember: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// =============================================================================
// DB helpers. Direct pgx queries against the contacts,
// groups, group_members tables. These are the source of
// truth for the test — the HTTP responses are
// side-effects, the DB state is the contract.
// =============================================================================

func dbContactStatus(ctx context.Context, pool *pgxpool.Pool, owner, target int64) string {
	var s string
	err := pool.QueryRow(ctx, `SELECT status FROM contacts WHERE owner_uin = $1 AND target_uin = $2`, owner, target).Scan(&s)
	if err != nil {
		return ""
	}
	return s
}

func dbGroupMember(ctx context.Context, pool *pgxpool.Pool, groupID string, uin int64) string {
	var role string
	err := pool.QueryRow(ctx, `SELECT role FROM group_members WHERE group_id = $1 AND uin = $2`, groupID, uin).Scan(&role)
	if err != nil {
		return ""
	}
	return role
}

func dbGroupMemberExists(ctx context.Context, pool *pgxpool.Pool, groupID string, uin int64) bool {
	var x int
	err := pool.QueryRow(ctx, `SELECT 1 FROM group_members WHERE group_id = $1 AND uin = $2`, groupID, uin).Scan(&x)
	return err == nil
}

func dbGroupOwner(ctx context.Context, pool *pgxpool.Pool, groupID string) int64 {
	var o int64
	err := pool.QueryRow(ctx, `SELECT owner_uin FROM groups WHERE id = $1`, groupID).Scan(&o)
	if err != nil {
		return 0
	}
	return o
}

func dbGroupExists(ctx context.Context, pool *pgxpool.Pool, groupID string) bool {
	var x int
	err := pool.QueryRow(ctx, `SELECT 1 FROM groups WHERE id = $1`, groupID).Scan(&x)
	return err == nil
}

// =============================================================================
// JWT + body helpers
// =============================================================================

func newJWTManager(pool *pgxpool.Pool) *jwt.Manager {
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379"})
	// The pg pool is created at the top of main() in this file
	// and passed in here so the JWT Manager can read
	// `users.session_epoch` on every Verify call (F-5).
	secret := os.Getenv("ICEQ_JWT_SECRET")
	if secret == "" {
		secret = jwtSecret
	}
	mgr, err := jwt.NewManager(secret, rdb, pool)
	if err != nil {
		fail("jwt manager: %v", err)
	}
	return mgr
}

func mintAccessToken(mgr *jwt.Manager, uin int64) string {
	// The manager bakes in the TTL (15m for access tokens)
	// so we just pick the type and read the result.
	res, err := mgr.Sign(uin, jwt.TokenTypeAccess)
	if err != nil {
		fail("mint access token: %v", err)
	}
	return res.Token
}

func jsonBody(v any) *bytes.Buffer {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(v)
	return &buf
}

func pgDSNFromEnv() string {
	if dsn := os.Getenv("ICEQ_PG_DSN"); dsn != "" {
		return dsn
	}
	if password := os.Getenv("POSTGRES_PASSWORD"); password != "" {
		return "postgres://postgres:" + password + "@postgres:5432/iceq?sslmode=disable"
	}
	return defaultPGDSN
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}

// Silence "imported and not used" if the test refactor
// drops a particular import. Cheap insurance.
var _ = strconv.Itoa
