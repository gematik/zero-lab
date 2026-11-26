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

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/kvtest"
	"github.com/gematik/zero-lab/go/kv/postgres"
)

// The tests of this file run what a deployment of several replicas does to one database: the suites of
// kvtest that take pods, each pod a store with a pool of its own, and for the start and the migration of
// a deployment each pod a process.

// The variables a pod's process reads: the connection URL of its database, the release it is of, and
// whether it applies the schema itself.
const (
	podURLEnv     = "KVTEST_POD_DATABASE_URL"
	podReleaseEnv = "KVTEST_POD_RELEASE"
	podMigrateEnv = "KVTEST_POD_MIGRATE"
)

// stepsOf are the schema steps of a release of the deployment tests: release 0 is this one, release 1 has
// an expand step more and the contract step that undoes it. The expand step holds the table locked for a
// while, as one that rewrites a large table does, so that pods restart while it runs and serve after it.
func stepsOf(release int) []postgres.Step {
	if release == 0 {
		return postgres.ReleasedSteps()
	}
	next := slices.Clone(ahead()[:released+2])
	next[released] = postgres.NewStep(released+1, "a probe column, slow to add", false,
		`ALTER TABLE kv ADD COLUMN probe text; SELECT pg_sleep(1)`)
	return next
}

// openPod opens the store of a pod's process from its environment.
func openPod(ctx context.Context) (kv.Store, error) {
	release, err := strconv.Atoi(os.Getenv(podReleaseEnv))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", podReleaseEnv, err)
	}
	opts := []postgres.Option{postgres.WithMark(kv.SealedMarker(nil))}
	if os.Getenv(podMigrateEnv) == "true" {
		opts = append(opts, postgres.WithMigrate())
	}
	return openSteps(ctx, os.Getenv(podURLEnv), stepsOf(release), opts...)
}

// podsOn opens the stores of pods on the database of a connection URL.
func podsOn(dsn string, opts ...postgres.Option) kvtest.Open {
	return func(pod kvtest.Pod) (kv.Store, error) {
		with := slices.Clone(opts)
		if pod.Ephemeral {
			with = append(with, postgres.WithEphemeral())
		}
		if pod.Mark != nil {
			with = append(with, postgres.WithMark(pod.Mark))
		}
		return openKV(context.Background(), dsn, with...)
	}
}

// pods opens the stores of pods on the database of TEST_DATABASE_URL.
func pods(t *testing.T, opts ...postgres.Option) kvtest.Open {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set: skipping the tests of several pods on Postgres (just kv-e2e-test)")
	}
	return podsOn(dsn, opts...)
}

// deployment is a database of its own with the migration jobs and the pods of a host.
func deployment(t *testing.T) kvtest.Deployment {
	t.Helper()
	dsn := freshDatabase(t)
	return kvtest.Deployment{
		Released: released,
		Migrate: func(ctx context.Context, _, release int, contract bool) (int, error) {
			address, user, password, with, err := apart(dsn, nil)
			if err != nil {
				return 0, err
			}
			db, err := postgres.OpenDB(address, user, password, with...)
			if err != nil {
				return 0, err
			}
			defer func() { _ = db.Close() }()
			var opts []postgres.MigrateOption
			if contract {
				opts = append(opts, postgres.Contract())
			}
			return postgres.MigrateSteps(ctx, db, stepsOf(release), opts...)
		},
		Start: func(t *testing.T, name string, _, release int, migrate bool) *kvtest.PodProcess {
			t.Helper()
			// The pod's process gets its database by a variable of its own: TestMain migrates the
			// database of TEST_DATABASE_URL, and a pod is not to.
			return kvtest.StartPod(t, name, "TEST_DATABASE_URL=", podURLEnv+"="+dsn,
				podReleaseEnv+"="+strconv.Itoa(release), podMigrateEnv+"="+strconv.FormatBool(migrate))
		},
		Applied: func(t *testing.T) []int {
			t.Helper()
			db := adminOf(t, dsn)
			var tables int
			if err := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name='kv_schema'`).Scan(&tables); err != nil {
				t.Fatal(err)
			}
			if tables == 0 {
				return nil
			}
			return appliedVersions(t, db)
		},
		Open: podsOn(dsn),
	}
}

// Server rules 17 and 22: the pods of a first installation start at once against an empty database, after
// a migration job or each applying the schema itself, and without either they refuse.
func TestPods_Rule22PodsThatStartTogetherOnAnEmptyDatabaseAllComeUp(t *testing.T) {
	kvtest.StartTogether(t, deployment)
}

// Server rule 22: a deployment goes from one release to the next while its pods serve.
func TestPods_Rule22ARollingMigrationKeepsThePodsServing(t *testing.T) {
	kvtest.RollingMigration(t, deployment(t))
}

// Server rule 5: sealed stores of several pods, in each class.
func TestPods_Rule5SealedRecordsOpenOnlyWhereAndAsWhatTheyWereSealed(t *testing.T) {
	kvtest.Sealing(t, pods(t))
}

// Server rules 5 and 22: a database that holds unsealed records of a release before sealing.
func TestPods_Rule5UnsealedRecordsOfBeforeAreNotTakenForSealedOnes(t *testing.T) {
	kvtest.Unsealed(t, pods(t))
}

// Server rule 22: the keys change as the guide for hosts says, with a keyring and with a keychain.
func TestPods_Rule22TheKeysChangeWhilePodsHoldDifferentFiles(t *testing.T) {
	kvtest.Rotation(t, pods(t))
}

// Server rules 5 and 22: sealed events while the keys of the feed change. The followers are told by
// notifications alone: they would look by themselves once an hour.
func TestPods_Rule22SealedEventsAcrossAChangeOfKeys(t *testing.T) {
	kvtest.SealedEvents(t, pods(t, postgres.WithFeedPoll(time.Hour)))
}

// Server rule 11: a revocation reaches the followers of other pods by its notification alone: they would
// look by themselves once an hour.
func TestPods_Rule11ARevocationReachesTheFollowersOfOtherPodsByItsNotification(t *testing.T) {
	kvtest.Revocations(t, pods(t, postgres.WithFeedPoll(time.Hour)))
}

// Server rule 11: the same while the connections the followers listen on are cut again and again, as a
// pooler or a failover does. What is lost with a notification is time: every event still arrives, once
// and in order.
func TestPods_Rule11ARevocationReachesTheFollowersWhoseListenersAreCutOff(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	db := adminOf(t, dsn)
	if _, err := postgres.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	stop, stopped := make(chan struct{}), make(chan int)
	go func() {
		cut := 0
		defer func() { stopped <- cut }()
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			var n int
			if err := db.QueryRow(`SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity
				WHERE datname = current_database() AND query = 'LISTEN kv_feed'`).Scan(&n); err == nil {
				cut += n
			}
		}
	}()
	kvtest.Revocations(t, podsOn(dsn, postgres.WithFeedPoll(200*time.Millisecond)))
	close(stop)
	if cut := <-stopped; cut == 0 {
		t.Error("no listening connection was cut: the test did not run what it is for")
	} else {
		t.Logf("%d listening connections were cut", cut)
	}
}

// Server rule 11: the worked case of the guide for hosts, logins of one user through several pods.
func TestPods_Rule11LoginsOfOneUserThroughSeveralPods(t *testing.T) {
	kvtest.Logins(t, pods(t))
}

// Server rule 22: a database that a release before the steps created, and that holds sealed records of
// that release, is adopted by a migration job: the pods of this release open every record, and the walk
// gives the records of before their marks.
func TestPods_Rule22ADatabaseOfBeforeTheStepsIsAdoptedWithItsSealedRecords(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	db := adminOf(t, dsn)
	if _, err := db.Exec(postgres.SchemaSQL); err != nil {
		t.Fatal(err)
	}
	// What a pod of that release ran: an upsert that names neither the mark nor when it was set.
	const upsertOfBefore = `INSERT INTO kv(key, value, expires_at) VALUES($1, $2, now() + interval '1 hour')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, created_at=now(), expires_at=excluded.expires_at`
	held := kv.NewMemory()
	before, err := kvtest.PodStore(held)
	if err != nil {
		t.Fatal(err)
	}
	const sessions = 5
	value := func(i int) string { return fmt.Sprintf("of before the steps, %d", i) }
	for i := range sessions {
		key := fmt.Sprintf("session:%d", i)
		if err := before.Set(ctx, key, []byte(value(i)), time.Hour); err != nil {
			t.Fatal(err)
		}
		record, _, err := held.Get(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(upsertOfBefore, key, record); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := openKV(ctx, dsn); err == nil {
		t.Fatal("a pod of this release starts on the database before its migration job ran")
	}
	if version, err := postgres.Migrate(ctx, db); err != nil || version != released {
		t.Fatalf("the migration job: version %d, err %v", version, err)
	}
	stores := make([]kv.Store, 2)
	for i := range stores {
		raw, err := podsOn(dsn)(kvtest.Pod{Number: i, Mark: kv.SealedMarker(nil)})
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		if stores[i], err = kvtest.PodStore(raw); err != nil {
			t.Fatal(err)
		}
	}
	for i := range sessions {
		key := fmt.Sprintf("session:%d", i)
		if got, found, err := stores[i%2].Get(ctx, key); err != nil || !found || string(got) != value(i) {
			t.Errorf("%s after the adoption: %q, found %v, err %v", key, got, found, err)
		}
	}
	resealer := stores[0].(kv.Resealer)
	if n, err := resealer.CountOthers(ctx, ""); err != nil || n != sessions {
		t.Fatalf("%d records count as without their mark, of %d of before the marks: %v", n, sessions, err)
	}
	others, err := resealer.Others(ctx, "", "", sessions+1)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range others {
		if resealed, err := resealer.Reseal(ctx, key); err != nil || !resealed {
			t.Errorf("%s: resealed %v, err %v", key, resealed, err)
		}
	}
	if n, err := stores[1].(kv.Resealer).CountOthers(ctx, ""); err != nil || n != 0 {
		t.Errorf("%d records are left without their mark: %v", n, err)
	}
	for i := range sessions {
		key := fmt.Sprintf("session:%d", i)
		if got, found, err := stores[1].Get(ctx, key); err != nil || !found || string(got) != value(i) {
			t.Errorf("%s after the walk: %q, found %v, err %v", key, got, found, err)
		}
	}
}
