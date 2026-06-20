package state

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenSQLite(filepath.Join(dir, "cli-state.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSetGetRoundtrip(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("k", []byte(`{"v":1}`)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := s.Get("k")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if string(got) != `{"v":1}` {
		t.Fatalf("value mismatch: %s", got)
	}
}

func TestGetMiss(t *testing.T) {
	s := newTestStore(t)
	_, ok, err := s.Get("absent")
	if err != nil || ok {
		t.Fatalf("expected miss, got ok=%v err=%v", ok, err)
	}
}

func TestTTLExpiryOnGet(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("k", []byte(`"v"`), Expire(20*time.Millisecond)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok, _ := s.Get("k"); !ok {
		t.Fatal("expected hit before expiry")
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok, _ := s.Get("k"); ok {
		t.Fatal("expected miss after expiry")
	}
}

func TestExpireAt(t *testing.T) {
	s := newTestStore(t)
	past := time.Now().Add(-time.Minute)
	if err := s.Set("k", []byte(`"v"`), ExpireAt(past)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok, _ := s.Get("k"); ok {
		t.Fatal("expected miss for already-expired entry")
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("k", []byte(`"v"`)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Delete("k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := s.Get("k"); ok {
		t.Fatal("expected miss after delete")
	}
	if err := s.Delete("k"); err != nil {
		t.Fatalf("Delete absent should be nop, got: %v", err)
	}
}

func TestKeysAndPrefix(t *testing.T) {
	s := newTestStore(t)
	for _, k := range []string{"epa:a", "epa:b", "pki:tsl:x", "other:c"} {
		if err := s.Set(k, []byte(`"v"`)); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}
	all, err := s.Keys("")
	if err != nil || len(all) != 4 {
		t.Fatalf("Keys all: %v %v", all, err)
	}
	epa, err := s.Keys("epa:")
	if err != nil {
		t.Fatalf("Keys prefix: %v", err)
	}
	if len(epa) != 2 || epa[0] != "epa:a" || epa[1] != "epa:b" {
		t.Fatalf("Keys epa prefix returned: %v", epa)
	}
	pki, err := s.Keys("pki:")
	if err != nil || len(pki) != 1 || pki[0] != "pki:tsl:x" {
		t.Fatalf("Keys pki prefix returned: %v %v", pki, err)
	}
}

func TestKeysHidesExpired(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("alive", []byte(`"v"`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("dead", []byte(`"v"`), ExpireAt(time.Now().Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	keys, err := s.Keys("")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "alive" {
		t.Fatalf("expected only alive, got %v", keys)
	}
}

func TestCleanup(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("alive", []byte(`"v"`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("dead", []byte(`"v"`), ExpireAt(time.Now().Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	removed, err := s.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
	keys, _ := s.Keys("")
	if len(keys) != 1 || keys[0] != "alive" {
		t.Fatalf("expected only alive remaining, got %v", keys)
	}
}

func TestPersistAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cli-state.db")
	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Set("k", []byte(`{"hello":"world"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	v, ok, err := s2.Get("k")
	if err != nil || !ok {
		t.Fatalf("expected hit on reopen, ok=%v err=%v", ok, err)
	}
	if string(v) != `{"hello":"world"}` {
		t.Fatalf("value mismatch: %s", v)
	}
}

func TestConcurrentReadsWithWrites(t *testing.T) {
	// WAL mode lets readers proceed while a writer is busy; with our
	// 1-connection pool and busy_timeout, a reader queued behind the writer
	// must succeed, not return "database is locked".
	s := newTestStore(t)
	if err := s.Set("k", []byte(`0`)); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			val := []byte{byte('0' + (i % 10))}
			val = append([]byte(`"`), val...)
			val = append(val, '"')
			if err := s.Set("k", val); err != nil {
				t.Errorf("Set: %v", err)
			}
		}(i)
	}
	for range 20 {
		wg.Go(func() {
			if _, _, err := s.Get("k"); err != nil {
				t.Errorf("Get: %v", err)
			}
		})
	}
	wg.Wait()
	if _, ok, err := s.Get("k"); err != nil || !ok {
		t.Fatalf("final Get: ok=%v err=%v", ok, err)
	}
}

func TestClosedStore(t *testing.T) {
	s := newTestStore(t)
	s.Close()
	if err := s.Set("k", []byte(`"v"`)); err == nil {
		t.Fatal("expected error after Close")
	}
	if _, _, err := s.Get("k"); err == nil {
		t.Fatal("expected error after Close")
	}
}

func TestNXAndXXSemantics(t *testing.T) {
	s := newTestStore(t)

	nx := SetOption(func(o *setOptions) { o.nx = true })
	xx := SetOption(func(o *setOptions) { o.xx = true })

	// XX on empty: no-op.
	if err := s.Set("k", []byte(`"first"`), xx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get("k"); ok {
		t.Fatal("XX should not create a missing key")
	}

	// NX on empty: creates.
	if err := s.Set("k", []byte(`"first"`), nx); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := s.Get("k"); string(v) != `"first"` {
		t.Fatalf("NX on empty should create; got %s", v)
	}

	// NX on existing: leaves the value alone.
	if err := s.Set("k", []byte(`"second"`), nx); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := s.Get("k"); string(v) != `"first"` {
		t.Fatalf("NX should not overwrite; got %s", v)
	}

	// XX on existing: overwrites.
	if err := s.Set("k", []byte(`"third"`), xx); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := s.Get("k"); string(v) != `"third"` {
		t.Fatalf("XX should overwrite existing; got %s", v)
	}
}

func TestKeepTTL(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("k", []byte(`"v1"`), Expire(100*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// Overwrite WITHOUT KeepTTL: TTL is cleared.
	if err := s.Set("k", []byte(`"v2"`)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if v, ok, _ := s.Get("k"); !ok || string(v) != `"v2"` {
		t.Fatalf("plain Set must reset TTL; ok=%v v=%s", ok, v)
	}

	if err := s.Set("k", []byte(`"v3"`), Expire(20*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	keepTTL := SetOption(func(o *setOptions) { o.keepTTL = true })
	if err := s.Set("k", []byte(`"v4"`), keepTTL); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok, _ := s.Get("k"); ok {
		t.Fatal("KeepTTL should have preserved the 20ms TTL")
	}
}

func TestSchemaInitIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cli-state.db")
	for i := range 3 {
		s, err := OpenSQLite(path)
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("close #%d: %v", i, err)
		}
	}
}

func TestSQLiteFileIsOpenableExternally(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cli-state.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("hello", []byte(`"world"`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Open the file with a fresh sql.DB and read the row directly — this is
	// the acceptance criterion that Rust/Kotlin can do the same.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var key string
	var value []byte
	if err := db.QueryRow(`SELECT key, value FROM kv WHERE key = ?`, "hello").Scan(&key, &value); err != nil {
		t.Fatalf("external read: %v", err)
	}
	if key != "hello" || string(value) != `"world"` {
		t.Fatalf("external read returned %q/%s", key, value)
	}
}

func TestExpiresAtIndexIsUsed(t *testing.T) {
	s := newTestStore(t)
	// Populate enough rows that the planner takes the index path seriously.
	for i := range 50 {
		key := "k" + strings.Repeat("a", i%5) + string(rune('0'+i%10))
		if err := s.Set(key, []byte(`"v"`), Expire(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN DELETE FROM kv WHERE expires_at IS NOT NULL AND expires_at <= ?`, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
		plan.WriteString("\n")
	}
	if !strings.Contains(plan.String(), "idx_kv_expires_at") {
		t.Fatalf("expected the cleanup query to use idx_kv_expires_at; plan was:\n%s", plan.String())
	}
}

func TestEntries(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("a", []byte(`1`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("b", []byte(`2`), Expire(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("c", []byte(`3`), ExpireAt(time.Now().Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	got, err := s.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 live entries, got %d (%v)", len(got), keysOf(got))
	}
	if _, ok := got["c"]; ok {
		t.Fatal("expired entry leaked into Entries result")
	}
	a := got["a"]
	if string(a.Value) != "1" {
		t.Fatalf("a.Value = %s", a.Value)
	}
	if a.ExpiresAt != nil {
		t.Fatal("a had no TTL")
	}
	b := got["b"]
	if b.ExpiresAt == nil {
		t.Fatal("b had a TTL")
	}
}

func keysOf(m map[string]Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestStoreInterfaceConformance is a build-time check that SQLiteStore still
// satisfies Store — catches accidental signature drift.
var _ Store = (*SQLiteStore)(nil)

// TestJSONRoundtripValueIsOpaque proves the store doesn't interpret the bytes.
func TestJSONRoundtripValueIsOpaque(t *testing.T) {
	s := newTestStore(t)
	type payload struct {
		Counter uint64 `json:"counter"`
		Nested  struct {
			Bytes []byte `json:"bytes"`
		} `json:"nested"`
	}
	in := payload{Counter: 12345}
	in.Nested.Bytes = []byte{0x00, 0x01, 0xff}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("p", raw); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get("p")
	if err != nil || !ok {
		t.Fatal("Get failed")
	}
	var out payload
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatal(err)
	}
	if out.Counter != in.Counter {
		t.Fatalf("counter %d != %d", out.Counter, in.Counter)
	}
	if string(out.Nested.Bytes) != string(in.Nested.Bytes) {
		t.Fatalf("nested bytes lost")
	}
}
