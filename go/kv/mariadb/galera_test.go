// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package mariadb_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/kvtest"
	"github.com/gematik/zero-lab/go/kv/mariadb"
)

const galeraEnv = "TEST_MARIADB_GALERA_DSNS"

// galeraDSNs are the DSNs of the writing nodes of one Galera cluster, separated by commas; the user and the
// password are those of the other tests.
func galeraDSNs(t *testing.T) []string {
	t.Helper()
	list := os.Getenv(galeraEnv)
	if list == "" {
		t.Skip(galeraEnv + " not set: skipping the Galera tests of kv/mariadb (just kv-mariadb-galera)")
	}
	dsns := strings.Split(list, ",")
	if len(dsns) < 2 {
		t.Fatal(galeraEnv + " names fewer than two nodes")
	}
	return dsns
}

// spread is a store over the nodes of a cluster that sends each call to the next node: what replicas
// behind a load balancer, each connected to a node of its own, do to one record.
type spread struct {
	nodes []kv.Store
	next  atomic.Uint64
}

func openSpread(t *testing.T, dsns []string, opts ...mariadb.Option) *spread {
	t.Helper()
	s := &spread{}
	for _, dsn := range dsns {
		node, err := openKV(context.Background(), dsn, opts...)
		if err != nil {
			t.Fatal(err)
		}
		s.nodes = append(s.nodes, node)
	}
	return s
}

func (s *spread) node() kv.Store { return s.nodes[s.next.Add(1)%uint64(len(s.nodes))] }

func (s *spread) Get(ctx context.Context, key string) ([]byte, bool, error) {
	return s.node().Get(ctx, key)
}

func (s *spread) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.node().Set(ctx, key, value, ttl)
}

func (s *spread) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return s.node().SetIfAbsent(ctx, key, value, ttl)
}

func (s *spread) SetMany(ctx context.Context, entries ...kv.Entry) error {
	return s.node().SetMany(ctx, entries...)
}

func (s *spread) Take(ctx context.Context, key string) ([]byte, bool, error) {
	return s.node().Take(ctx, key)
}

func (s *spread) Delete(ctx context.Context, key string) error { return s.node().Delete(ctx, key) }

func (s *spread) Keys(ctx context.Context, prefix string) ([]string, error) {
	return s.node().Keys(ctx, prefix)
}

func (s *spread) Cleanup(ctx context.Context) (int, error) { return s.node().Cleanup(ctx) }

func (s *spread) Swap(ctx context.Context, key string, old, value []byte, ttl time.Duration) (bool, error) {
	return s.node().(kv.Swapper).Swap(ctx, key, old, value, ttl)
}

func (s *spread) MarkedOther(ctx context.Context, prefix, mark, after string, limit int) ([]string, error) {
	return s.node().(kv.Marker).MarkedOther(ctx, prefix, mark, after, limit)
}

func (s *spread) CountMarkedOther(ctx context.Context, prefix, mark string) (int, error) {
	return s.node().(kv.Marker).CountMarkedOther(ctx, prefix, mark)
}

func (s *spread) Marks(ctx context.Context, prefix string) (map[string]int, error) {
	return s.node().(kv.Marker).Marks(ctx, prefix)
}

func (s *spread) Tx(ctx context.Context, fn func(tx kv.Tx) error) error {
	return s.node().(kv.Transactor).Tx(ctx, fn)
}

func (s *spread) Publish(ctx context.Context, topic string, event []byte, retention time.Duration) (kv.Cursor, error) {
	return s.node().(kv.Feed).Publish(ctx, topic, event, retention)
}

func (s *spread) Follow(ctx context.Context, topic string, from kv.Cursor) (<-chan kv.Event, error) {
	return s.node().(kv.Feed).Follow(ctx, topic, from)
}

func (s *spread) Latest(ctx context.Context, topic string) (kv.Cursor, error) {
	return s.node().(kv.Feed).Latest(ctx, topic)
}

func (s *spread) Durability() kv.Durability { return kv.DurabilityOf(s.nodes[0]) }

func (s *spread) Close() error {
	for _, node := range s.nodes {
		_ = node.Close()
	}
	return nil
}

func migratedCluster(t *testing.T) []string {
	t.Helper()
	dsns := galeraDSNs(t)
	if _, err := mariadb.Migrate(context.Background(), adminOf(t, dsns[0])); err != nil {
		t.Fatal(err)
	}
	return dsns
}

// The whole contract holds when every call goes through another writing node of a Galera cluster: a value
// written through one node is read through the next, and of many that take, set or swap one record at
// once through different nodes, one wins. Locks of one node do not make that so: the cluster refuses all
// but one of the writers at commit, and the others try again and find the winner's record.
func TestGalera_Task429TheContractHoldsThroughDifferentWritingNodes(t *testing.T) {
	dsns := migratedCluster(t)
	kvtest.Store(t, func(t *testing.T) kv.Store { return openSpread(t, dsns) })
}

func TestGalera_Task429TheMarkerContractHoldsThroughDifferentWritingNodes(t *testing.T) {
	dsns := migratedCluster(t)
	kvtest.Marker(t, func(t *testing.T, mark func(string, []byte) string) kv.Store {
		return openSpread(t, dsns, mariadb.WithMark(mark))
	})
}

// The feed holds through different writing nodes: publishers on three nodes raise one counter, and the
// cluster lets one of them commit at a time, so that the numbers have no gap and a follower on any node
// steps over no event.
func TestGalera_Task432TheFeedContractHoldsThroughDifferentWritingNodes(t *testing.T) {
	dsns := migratedCluster(t)
	kvtest.Feed(t, func(t *testing.T) kv.Store { return openSpread(t, dsns, mariadb.WithFeedPoll(testPoll)) })
}

// Transactions hold through different writing nodes for what they write: of many that read a record and
// write it, none is lost, and records under a root that every transaction reads first and writes last
// change together. The cluster refuses all but one of the transactions that wrote the same record, and
// the others run again.
func TestGalera_Task432TheTxContractHoldsThroughDifferentWritingNodes(t *testing.T) {
	dsns := migratedCluster(t)
	kvtest.Tx(t, func(t *testing.T) kv.Store { return openSpread(t, dsns) })
}

// The ephemeral class holds through different writing nodes as the durable one does.
func TestGalera_Task431TheEphemeralContractHoldsThroughDifferentWritingNodes(t *testing.T) {
	dsns := migratedCluster(t)
	open := func(t *testing.T) kv.Store { return openSpread(t, dsns, mariadb.WithEphemeral()) }
	kvtest.Store(t, open)
	kvtest.Ephemeral(t, open)
}

// What a transaction only read is not protected across writing nodes: the lock of Get is one node's, and
// the cluster checks writes against writes. Two transactions that each read a record the other writes,
// through different nodes, can both commit: neither wrote what the other wrote. This is why records that
// change together hang under a root that is written. Measured, not asserted: how often it happens here.
func TestGalera_Task432ARecordOnlyReadIsNotProtectedAcrossNodes(t *testing.T) {
	ctx := context.Background()
	dsns := migratedCluster(t)
	s := openSpread(t, dsns)
	defer s.Close()
	const rounds = 100
	both := 0
	for i := range rounds {
		a := fmt.Sprintf("skew:%d:%d:a", time.Now().UnixNano(), i)
		b := fmt.Sprintf("skew:%d:%d:b", time.Now().UnixNano(), i)
		// Each takes the place only if the other has not: read the other's record, write one's own.
		claim := func(node kv.Store, mine, other string) func() error {
			return func() error {
				return node.(kv.Transactor).Tx(ctx, func(tx kv.Tx) error {
					if _, found, err := tx.Get(ctx, other); err != nil || found {
						return err
					}
					return tx.Set(ctx, mine, []byte("taken"), time.Minute)
				})
			}
		}
		errs := make(chan error, 2)
		go func() { errs <- claim(s.nodes[0], a, b)() }()
		go func() { errs <- claim(s.nodes[1], b, a)() }()
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		_, hasA, _ := s.nodes[2].Get(ctx, a)
		_, hasB, _ := s.nodes[2].Get(ctx, b)
		if hasA && hasB {
			both++
		}
		_ = s.nodes[0].Delete(ctx, a)
		_ = s.nodes[0].Delete(ctx, b)
	}
	t.Logf("of %d pairs of transactions that each read what the other wrote, through two nodes, both committed in %d", rounds, both)
}

// A node applies what the cluster committed a moment after the commit. A session that waits for it
// (wsrep_sync_wait, on by itself where the server is in a cluster) finds through one node what was just
// written through another, every time: an authorization code set by one replica and taken by another is
// not lost between them.
func TestGalera_Task429AValueWrittenThroughOneNodeIsFoundThroughAnotherAtOnce(t *testing.T) {
	ctx := context.Background()
	dsns := migratedCluster(t)
	s := openSpread(t, dsns)
	defer s.Close()
	const rounds = 300
	base := fmt.Sprintf("across:%d:", time.Now().UnixNano())
	for i := range rounds {
		key := fmt.Sprintf("%s%d", base, i)
		writer, reader := s.nodes[i%len(s.nodes)], s.nodes[(i+1)%len(s.nodes)]
		if err := writer.Set(ctx, key, []byte("v"), time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, found, err := reader.Take(ctx, key); err != nil || !found {
			t.Fatalf("round %d: taken through another node: found %v, err %v", i, found, err)
		}
	}
}

// What the wait is for, measured and not asserted: without it, how often a value written through one node
// is not yet there through another.
func TestGalera_Task429WithoutTheWaitAValueMayNotBeFoundYet(t *testing.T) {
	ctx := context.Background()
	dsns := migratedCluster(t)
	s := openSpread(t, dsns, mariadb.WithSyncWait(mariadb.SyncWaitNever))
	defer s.Close()
	const rounds = 300
	base := fmt.Sprintf("nowait:%d:", time.Now().UnixNano())
	missed := 0
	for i := range rounds {
		key := fmt.Sprintf("%s%d", base, i)
		writer, reader := s.nodes[i%len(s.nodes)], s.nodes[(i+1)%len(s.nodes)]
		if err := writer.Set(ctx, key, []byte("v"), time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, found, err := reader.Get(ctx, key); err != nil {
			t.Fatal(err)
		} else if !found {
			missed++
		}
		_ = writer.Delete(ctx, key)
	}
	t.Logf("without wsrep_sync_wait %d of %d values were not yet found through another node", missed, rounds)
}

// Migration jobs that run through different nodes at once all succeed: DDL is replicated in one order to
// every node, and a step that ran already changes nothing.
func TestGalera_Task429MigratorsThroughDifferentNodesAtOnceSucceedForAll(t *testing.T) {
	dsns := galeraDSNs(t)
	for range 3 {
		fresh := freshDatabase(t, dsns[0])
		name := fresh[strings.LastIndex(fresh, "/")+1:]
		if i := strings.Index(name, "?"); i >= 0 {
			name = name[:i]
		}
		var all []string
		for _, dsn := range dsns {
			head, query, _ := strings.Cut(dsn, "?")
			node := head[:strings.LastIndex(head, "/")+1] + name
			if query != "" {
				node += "?" + query
			}
			all = append(all, node)
		}
		migrateTogether(t, all, 9)
		for _, dsn := range all {
			if got := appliedVersions(t, adminOf(t, dsn)); fmt.Sprint(got) != upTo(released+3) {
				t.Errorf("applied %v", got)
			}
		}
	}
}
