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
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/kvtest"
	"github.com/gematik/zero-lab/go/kv/mariadb"
)

// The tests of this file run what a deployment of several replicas does to one database: the suites of
// kvtest that take pods, each pod a store with a pool of its own, and for the start and the migration of
// a deployment each pod a process. Each runs against one node and, as TestGalera, with the pods spread
// over the writing nodes of a cluster.

// The variables a pod's process reads: the DSN of its node, the release it is of, and whether it applies
// the schema itself. The user and the password are those of the tests.
const (
	podDSNEnv     = "KVTEST_POD_DSN"
	podReleaseEnv = "KVTEST_POD_RELEASE"
	podMigrateEnv = "KVTEST_POD_MIGRATE"
)

// stepsOf are the schema steps of a release of the deployment tests: release 0 is this one, release 1 has
// an expand step more and the contract step that undoes it.
func stepsOf(release int) []mariadb.Step {
	if release == 0 {
		return mariadb.ReleasedSteps()
	}
	return ahead()[:released+2]
}

// openPod opens the store of a pod's process from its environment.
func openPod(ctx context.Context) (kv.Store, error) {
	release, err := strconv.Atoi(os.Getenv(podReleaseEnv))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", podReleaseEnv, err)
	}
	opts := []mariadb.Option{mariadb.WithMark(kv.SealedMarker(nil))}
	if os.Getenv(podMigrateEnv) == "true" {
		opts = append(opts, mariadb.WithMigrate())
	}
	return openSteps(ctx, os.Getenv(podDSNEnv), stepsOf(release), opts...)
}

// podsOn opens the stores of pods on one database, reached through the nodes of dsns: a pod's number
// picks its node.
func podsOn(dsns []string, opts ...mariadb.Option) kvtest.Open {
	return func(pod kvtest.Pod) (kv.Store, error) {
		with := slices.Clone(opts)
		if pod.Ephemeral {
			with = append(with, mariadb.WithEphemeral())
		}
		if pod.Mark != nil {
			with = append(with, mariadb.WithMark(pod.Mark))
		}
		return openKV(context.Background(), dsns[pod.Number%len(dsns)], with...)
	}
}

// onNodes are the DSNs of another database of the same nodes.
func onNodes(dsns []string, database string) []string {
	out := make([]string, len(dsns))
	for i, dsn := range dsns {
		out[i] = dsn[:strings.LastIndex(dsn, "/")+1] + database
	}
	return out
}

// deployment is a database of its own, reached through the nodes of dsns, with the migration jobs and
// the pods of a host.
func deployment(dsns []string) func(t *testing.T) kvtest.Deployment {
	return func(t *testing.T) kvtest.Deployment {
		t.Helper()
		fresh := freshDatabase(t, dsns[0])
		nodes := onNodes(dsns, fresh[strings.LastIndex(fresh, "/")+1:])
		known(t, nodes)
		return kvtest.Deployment{
			Released: released,
			Migrate: func(ctx context.Context, number, release int, contract bool) (int, error) {
				db, err := openDB(nodes[number%len(nodes)])
				if err != nil {
					return 0, err
				}
				defer func() { _ = db.Close() }()
				var opts []mariadb.MigrateOption
				if contract {
					opts = append(opts, mariadb.Contract())
				}
				return mariadb.MigrateSteps(ctx, db, stepsOf(release), opts...)
			},
			Start: func(t *testing.T, name string, number, release int, migrate bool) *kvtest.PodProcess {
				t.Helper()
				// The pod's process gets its database by a variable of its own: TestMain migrates the
				// database of the tests' variable, and a pod is not to.
				return kvtest.StartPod(t, name, dsnEnv+"=", galeraEnv+"=", podDSNEnv+"="+nodes[number%len(nodes)],
					podReleaseEnv+"="+strconv.Itoa(release), podMigrateEnv+"="+strconv.FormatBool(migrate))
			},
			Applied: func(t *testing.T) []int {
				t.Helper()
				db := adminOf(t, nodes[0])
				// One session, which waits for what the cluster committed through the other nodes.
				db.SetMaxOpenConns(1)
				if len(nodes) > 1 {
					if _, err := db.Exec(`SET SESSION wsrep_sync_wait = 7`); err != nil {
						t.Fatal(err)
					}
				}
				var tables int
				if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.tables
					WHERE table_schema=DATABASE() AND table_name='kv_schema'`).Scan(&tables); err != nil {
					t.Fatal(err)
				}
				if tables == 0 {
					return nil
				}
				return appliedVersions(t, db)
			},
			Open: podsOn(nodes),
		}
	}
}

// known waits until every node knows the database of its DSN: a cluster applies a CREATE DATABASE on the
// other nodes after the one it was made through has answered, and a migration job or a pod that connects
// through another node at once would find no database.
func known(t *testing.T, nodes []string) {
	t.Helper()
	for _, node := range nodes {
		db := adminOf(t, node)
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			err := db.Ping()
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("a node does not know the database: %v", err)
			}
		}
	}
}

// podSuites are the suites of kvtest that take pods, by the name of what each proves.
var podSuites = []struct {
	name string
	run  func(t *testing.T, dsns []string)
}{
	// Server rules 17 and 22: the pods of a first installation start at once against an empty database,
	// after a migration job or each applying the schema itself, and without either they refuse.
	{"Rule22PodsThatStartTogetherOnAnEmptyDatabaseAllComeUp", func(t *testing.T, dsns []string) {
		kvtest.StartTogether(t, deployment(dsns))
	}},
	// Server rule 22: a deployment goes from one release to the next while its pods serve.
	{"Rule22ARollingMigrationKeepsThePodsServing", func(t *testing.T, dsns []string) {
		kvtest.RollingMigration(t, deployment(dsns)(t))
	}},
	// Server rule 5: sealed stores of several pods, in each class.
	{"Rule5SealedRecordsOpenOnlyWhereAndAsWhatTheyWereSealed", func(t *testing.T, dsns []string) {
		kvtest.Sealing(t, podsOn(dsns))
	}},
	// Server rules 5 and 22: a database that holds unsealed records of a release before sealing.
	{"Rule5UnsealedRecordsOfBeforeAreNotTakenForSealedOnes", func(t *testing.T, dsns []string) {
		kvtest.Unsealed(t, podsOn(dsns))
	}},
	// Server rule 22: the keys change as the guide for hosts says, with a keyring and with a keychain.
	{"Rule22TheKeysChangeWhilePodsHoldDifferentFiles", func(t *testing.T, dsns []string) {
		kvtest.Rotation(t, podsOn(dsns))
	}},
	// Server rules 5 and 22: sealed events while the keys of the feed change.
	{"Rule22SealedEventsAcrossAChangeOfKeys", func(t *testing.T, dsns []string) {
		kvtest.SealedEvents(t, podsOn(dsns, mariadb.WithFeedPoll(testPoll)))
	}},
	// Server rule 11: a revocation reaches the followers of other pods, which look for it.
	{"Rule11ARevocationReachesTheFollowersOfOtherPods", func(t *testing.T, dsns []string) {
		kvtest.Revocations(t, podsOn(dsns, mariadb.WithFeedPoll(testPoll)))
	}},
	// Server rule 11: the worked case of the guide for hosts, logins of one user through several pods.
	{"Rule11LoginsOfOneUserThroughSeveralPods", func(t *testing.T, dsns []string) {
		kvtest.Logins(t, podsOn(dsns, mariadb.WithFeedPoll(testPoll)))
	}},
}

func TestPods(t *testing.T) {
	dsns := []string{testDSN(t)}
	for _, suite := range podSuites {
		t.Run(suite.name, func(t *testing.T) { suite.run(t, dsns) })
	}
}

// The same with the pods spread over the writing nodes of a cluster: every pod, every migration job and
// every follower reaches the database through a node of its own.
func TestGalera_Pods(t *testing.T) {
	dsns := migratedCluster(t)
	for _, suite := range podSuites {
		t.Run(suite.name, func(t *testing.T) { suite.run(t, dsns) })
	}
}
