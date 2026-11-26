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

package kvtest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/schema"
)

// podEnv names the pod a process is. A test binary that finds it set was started by [StartPod] and serves
// as that pod instead of running its tests ([IsPod], [ServePod]).
const podEnv = "KVTEST_POD"

const (
	// podPrefix is the prefix of every key of the pods' processes, podPurpose the purpose of their seal.
	podPrefix  = "kvtest:pod:"
	podPurpose = "kvtest pods"
	// podStanding is a record that is there before the first pod starts and that every pod reads again
	// and again.
	podStanding = podPrefix + "standing"
	// podPace is how long a pod rests between two rounds of its work.
	podPace = 3 * time.Millisecond
)

// IsPod reports whether this process is a pod that [StartPod] started.
func IsPod() bool { return os.Getenv(podEnv) != "" }

// PodStore is a store as the pods' processes wrap theirs: sealed, under the key and the purpose they all
// have. The store below keeps the marks of kv.SealedMarker.
func PodStore(raw kv.Store) (kv.Store, error) {
	keys, err := parseRing("a")
	if err != nil {
		return nil, err
	}
	return kv.NewSealed(raw, keys, podPurpose, kv.WithSealedExpiry(time.Now)), nil
}

// oneLine is an error as one line of a pod's answers.
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

// ServePod is the life of a pod's process, which a test binary runs from its TestMain when [IsPod]: it
// opens its store, says "up" or why it was refused, and then answers the lines of its standard input until
// it is told to stop. Told to serve, it does beside that, round after round, what a replica of an
// authorization server does to its store: it writes a session and reads it, counts a login up under a
// root record in a transaction, and reads a record that stood before it served.
//
//	serve               ok, and the rounds begin
//	set <key> <value>   ok
//	get <key>           value <value> | absent
//	take <key>          value <value> | absent
//	stats               stats <rounds> <failed rounds> <counted logins> <first failure>
//	stop                stats …, and the process ends
//
// and "error <text>" where the store failed. It returns the exit code of the process.
func ServePod(open func(ctx context.Context) (kv.Store, error)) int {
	ctx := context.Background()
	out := bufio.NewWriter(os.Stdout)
	say := func(format string, args ...any) {
		_, _ = fmt.Fprintf(out, format+"\n", args...)
		_ = out.Flush()
	}
	raw, err := open(ctx)
	if err != nil {
		say("refused %t %s", errors.Is(err, schema.ErrVersion), oneLine(err))
		return 0
	}
	defer func() { _ = raw.Close() }()
	store, err := PodStore(raw)
	if err != nil {
		say("refused false %s", oneLine(err))
		return 0
	}
	work := &podWork{name: os.Getenv(podEnv), store: store, stop: make(chan struct{}), done: make(chan struct{})}
	say("up")
	found := func(value []byte, found bool, err error) string {
		switch {
		case err != nil:
			return "error " + oneLine(err)
		case !found:
			return "absent"
		}
		return "value " + string(value)
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		fields := strings.Fields(in.Text())
		switch {
		case len(fields) == 3 && fields[0] == "set":
			if err := store.Set(ctx, podPrefix+fields[1], []byte(fields[2]), time.Hour); err != nil {
				say("error %s", oneLine(err))
				continue
			}
			say("ok")
		case len(fields) == 2 && fields[0] == "get":
			say("%s", found(store.Get(ctx, podPrefix+fields[1])))
		case len(fields) == 2 && fields[0] == "take":
			say("%s", found(store.Take(ctx, podPrefix+fields[1])))
		case len(fields) == 1 && fields[0] == "serve" && !work.serving:
			work.serving = true
			go work.run(ctx)
			say("ok")
		case len(fields) == 1 && fields[0] == "stats":
			say("%s", work.stats())
		case len(fields) == 1 && fields[0] == "stop":
			if work.serving {
				close(work.stop)
				<-work.done
			}
			say("%s", work.stats())
			return 0
		default:
			say("error the pod does not know this line")
		}
	}
	// The test that started the pod is gone.
	return 1
}

// podWork is the rounds of a pod and what came of them.
type podWork struct {
	name    string
	store   kv.Store
	serving bool
	stop    chan struct{}
	done    chan struct{}

	mu                     sync.Mutex
	rounds, failed, logins int
	first                  string
}

func (w *podWork) stats() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	first := w.first
	if first == "" {
		first = "-"
	}
	return fmt.Sprintf("stats %d %d %d %s", w.rounds, w.failed, w.logins, first)
}

func (w *podWork) run(ctx context.Context) {
	defer close(w.done)
	for n := 0; ; n++ {
		select {
		case <-w.stop:
			return
		case <-time.After(podPace):
		}
		counted, err := w.round(ctx, n)
		w.mu.Lock()
		w.rounds++
		if counted {
			w.logins++
		}
		if err != nil {
			w.failed++
			if w.first == "" {
				w.first = oneLine(err)
			}
		}
		w.mu.Unlock()
	}
}

func (w *podWork) round(ctx context.Context, n int) (counted bool, err error) {
	key, value := fmt.Sprintf("%swork:%s:%d", podPrefix, w.name, n%32), fmt.Appendf(nil, "session %d of %s", n, w.name)
	if err := w.store.Set(ctx, key, value, time.Hour); err != nil {
		return false, fmt.Errorf("writing a session: %w", err)
	}
	if got, found, err := w.store.Get(ctx, key); err != nil || !found || !bytes.Equal(got, value) {
		return false, errors.Join(fmt.Errorf("the session just written: %q, found %v", got, found), err)
	}
	if got, found, err := w.store.Get(ctx, podStanding); err != nil || !found || string(got) != "stands" {
		return false, errors.Join(fmt.Errorf("the record of before the pods: %q, found %v", got, found), err)
	}
	err = inTx(ctx, w.store, func(tx kv.Tx) error {
		root, _, err := tx.Get(ctx, podPrefix+"root:"+w.name)
		if err != nil {
			return err
		}
		logins, _ := strconv.Atoi(string(root))
		return tx.Set(ctx, podPrefix+"root:"+w.name, []byte(strconv.Itoa(logins+1)), time.Hour)
	})
	if err != nil {
		return false, fmt.Errorf("counting a login: %w", err)
	}
	return true, nil
}

// PodProcess is a pod as a process of its own: the test binary, started again ([StartPod]).
type PodProcess struct {
	Name  string
	cmd   *exec.Cmd
	in    *bufio.Writer
	lines chan string
	log   *podLog
	// asking keeps the lines of two goroutines that ask one pod apart.
	asking sync.Mutex
}

// podLog is what a pod wrote to its standard error, which is read while the pod may still write.
type podLog struct {
	mu   sync.Mutex
	text bytes.Buffer
}

func (l *podLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.Write(p)
}

func (l *podLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.String()
}

// PodStats is what a pod says of its rounds.
type PodStats struct {
	Rounds, Failed, Logins int
	// First is the first failure of a round, "-" for none.
	First string
}

// podAnswer is how long a pod has to answer a line, and to say that it is up.
const podAnswer = 60 * time.Second

// StartPod starts this test binary again as a pod with the given name, and with env added to this
// process's environment (an entry "NAME=" takes a variable away). The binary's TestMain has to call
// [ServePod] when [IsPod]. The process is ended with the test.
func StartPod(t *testing.T, name string, env ...string) *PodProcess {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := &PodProcess{Name: name, cmd: exec.Command(binary), lines: make(chan string, 16), log: &podLog{}}
	p.cmd.Env = append(append(os.Environ(), env...), podEnv+"="+name)
	p.cmd.Stderr = p.log
	stdin, err := p.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.in = bufio.NewWriter(stdin)
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(p.lines)
		lines := bufio.NewScanner(stdout)
		for lines.Scan() {
			p.lines <- lines.Text()
		}
	}()
	t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	})
	return p
}

// line is the next line the pod says, or an error with what it logged.
func (p *PodProcess) line() (string, error) {
	select {
	case line, ok := <-p.lines:
		if !ok {
			return "", fmt.Errorf("the pod %s ended without an answer; it logged: %s", p.Name, p.log.String())
		}
		return line, nil
	case <-time.After(podAnswer):
		return "", fmt.Errorf("the pod %s did not answer within %v", p.Name, podAnswer)
	}
}

// Up waits until the pod has opened its store or was refused. refusal is the error of its Open, and
// version whether that error is a schema.ErrVersion.
func (p *PodProcess) Up() (up, version bool, refusal string, err error) {
	line, err := p.line()
	if err != nil {
		return false, false, "", err
	}
	if line == "up" {
		return true, false, "", nil
	}
	fields := strings.SplitN(line, " ", 3)
	if len(fields) != 3 || fields[0] != "refused" {
		return false, false, "", fmt.Errorf("the pod %s said %q at its start", p.Name, line)
	}
	return false, fields[1] == "true", fields[2], nil
}

// Ask sends the pod a line ([ServePod]) and returns its answer.
func (p *PodProcess) Ask(line string) (string, error) {
	p.asking.Lock()
	defer p.asking.Unlock()
	if _, err := p.in.WriteString(line + "\n"); err != nil {
		return "", err
	}
	if err := p.in.Flush(); err != nil {
		return "", err
	}
	return p.line()
}

func (p *PodProcess) statsOf(line string) (PodStats, error) {
	answer, err := p.Ask(line)
	if err != nil {
		return PodStats{}, err
	}
	fields := strings.SplitN(answer, " ", 5)
	if len(fields) != 5 || fields[0] != "stats" {
		return PodStats{}, fmt.Errorf("the pod %s answered %q", p.Name, answer)
	}
	stats := PodStats{First: fields[4]}
	for i, to := range []*int{&stats.Rounds, &stats.Failed, &stats.Logins} {
		if *to, err = strconv.Atoi(fields[i+1]); err != nil {
			return PodStats{}, fmt.Errorf("the pod %s answered %q", p.Name, answer)
		}
	}
	return stats, nil
}

// Stats asks the pod for what came of its rounds so far.
func (p *PodProcess) Stats() (PodStats, error) { return p.statsOf("stats") }

// Stop ends the pod and returns what came of its rounds.
func (p *PodProcess) Stop() (PodStats, error) {
	stats, err := p.statsOf("stop")
	if err != nil {
		return PodStats{}, err
	}
	return stats, p.cmd.Wait()
}

// Deployment is a database of its own and what a host runs against it: migration jobs and pods of two
// releases. Release 0 is the one under test. Release 1 has an expand step more, and after it a contract
// step, which it works with and without; a backend makes the two from its test hooks.
type Deployment struct {
	// Released is how many schema steps release 0 has.
	Released int
	// Migrate runs a migration job of a release over connections of its own, through the node that number
	// picks, with or without the contract step, and returns the version of the schema after it.
	Migrate func(ctx context.Context, number, release int, contract bool) (int, error)
	// Start starts a pod of a release as a process ([StartPod]); with migrate the pod applies the schema
	// itself when it opens its store.
	Start func(t *testing.T, name string, number, release int, migrate bool) *PodProcess
	// Applied returns the versions of the steps the database records, in order.
	Applied func(t *testing.T) []int
	// Open opens a store of the test's own on the database.
	Open Open
}

// upTo is the versions 1 to n.
func upTo(n int) []int {
	versions := make([]int, n)
	for i := range versions {
		versions[i] = i + 1
	}
	return versions
}

// serve has pods that are up begin their rounds.
func serve(t *testing.T, pods ...*PodProcess) {
	t.Helper()
	for _, pod := range pods {
		ask(t, pod, "serve", "ok")
	}
}

// up waits for pods that have to come up.
func up(t *testing.T, pods ...*PodProcess) {
	t.Helper()
	for _, pod := range pods {
		started, _, refusal, err := pod.Up()
		if err != nil {
			t.Fatal(err)
		}
		if !started {
			t.Fatalf("the pod %s does not come up: %s", pod.Name, refusal)
		}
	}
}

// served waits until each pod has done more rounds than it had, and fails if a round of it failed.
func served(t *testing.T, pods ...*PodProcess) {
	t.Helper()
	const more = 20
	for _, pod := range pods {
		from, err := pod.Stats()
		if err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(wait); ; time.Sleep(10 * time.Millisecond) {
			now, err := pod.Stats()
			if err != nil {
				t.Fatal(err)
			}
			if now.Failed != 0 {
				t.Fatalf("the pod %s failed in %d of %d rounds, first: %s", pod.Name, now.Failed, now.Rounds, now.First)
			}
			if now.Rounds >= from.Rounds+more {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the pod %s does not serve: %d rounds, then %d", pod.Name, from.Rounds, now.Rounds)
			}
		}
	}
}

// stopped ends pods and holds what they say they did against the database: no round failed, and the root
// record of each counts exactly the logins the pod counted.
func stopped(t *testing.T, store kv.Store, pods ...*PodProcess) {
	t.Helper()
	for _, pod := range pods {
		stats, err := pod.Stop()
		if err != nil {
			t.Fatal(err)
		}
		if stats.Failed != 0 || stats.Rounds == 0 {
			t.Errorf("the pod %s failed in %d of %d rounds, first: %s", pod.Name, stats.Failed, stats.Rounds, stats.First)
		}
		root, _, err := store.Get(context.Background(), podPrefix+"root:"+pod.Name)
		if err != nil || string(root) != strconv.Itoa(stats.Logins) {
			t.Errorf("the pod %s counted %d logins, its root record says %q: %v", pod.Name, stats.Logins, root, err)
		}
	}
}

// ask sends a pod a line and holds its answer against the one expected.
func ask(t *testing.T, pod *PodProcess, line, want string) {
	t.Helper()
	if got, err := pod.Ask(line); err != nil || got != want {
		t.Fatalf("the pod %s, asked %q, answered %q, want %q: %v", pod.Name, line, got, want, err)
	}
}

// testStore opens the test's own store on a deployment, as the pods wrap theirs, with the record the
// pods read standing.
func (d Deployment) testStore(t *testing.T) kv.Store {
	t.Helper()
	raw, err := d.Open(Pod{Mark: kv.SealedMarker(nil)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	store, err := PodStore(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(context.Background(), podStanding, []byte("stands"), 0); err != nil {
		t.Fatal(err)
	}
	return store
}

// StartTogether starts the pods of a first installation at once, each a process, against an empty
// database that fresh makes (server rules 17 and 22): after a migration job they all come up; without a
// job, each applying the schema itself, they all come up and the database records every step; and with
// neither every one of them refuses to start and names the versions.
func StartTogether(t *testing.T, fresh func(t *testing.T) Deployment) {
	t.Helper()
	ctx := context.Background()
	const pods = 6
	start := func(t *testing.T, d Deployment, migrate bool) []*PodProcess {
		t.Helper()
		started := make([]*PodProcess, pods)
		for i := range started {
			started[i] = d.Start(t, fmt.Sprintf("first-%d", i), i, 0, migrate)
		}
		return started
	}

	t.Run("after migration jobs that ran at once, all pods come up and serve", func(t *testing.T) {
		d := fresh(t)
		errs := make(chan error, 2)
		for i := range 2 {
			go func() {
				version, err := d.Migrate(ctx, i, 0, false)
				if err == nil && version != d.Released {
					err = fmt.Errorf("the job leaves the schema at version %d", version)
				}
				errs <- err
			}()
		}
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		store := d.testStore(t)
		started := start(t, d, false)
		up(t, started...)
		serve(t, started...)
		served(t, started...)
		stopped(t, store, started...)
		if got := d.Applied(t); !slices.Equal(got, upTo(d.Released)) {
			t.Errorf("the database records the steps %v", got)
		}
	})

	t.Run("without a job, each pod applying the schema itself, all come up and serve on a schema that records every step", func(t *testing.T) {
		d := fresh(t)
		started := start(t, d, true)
		up(t, started...)
		if got := d.Applied(t); !slices.Equal(got, upTo(d.Released)) {
			t.Errorf("the database records the steps %v", got)
		}
		store := d.testStore(t)
		serve(t, started...)
		served(t, started...)
		stopped(t, store, started...)
	})

	t.Run("without a job and without leave to apply the schema, every pod refuses to start and names the versions", func(t *testing.T) {
		d := fresh(t)
		for _, pod := range start(t, d, false) {
			started, version, refusal, err := pod.Up()
			if err != nil {
				t.Fatal(err)
			}
			if started || !version || !strings.Contains(refusal, "version 0") || !strings.Contains(refusal, fmt.Sprintf("needs %d", d.Released)) {
				t.Errorf("the pod %s on an empty database: up %v, a version error %v: %s", pod.Name, started, version, refusal)
			}
		}
		if got := d.Applied(t); len(got) != 0 {
			t.Errorf("a pod that was refused left steps behind: %v", got)
		}
	})
}

// RollingMigration takes a deployment from one release to the next while its pods serve, each pod a
// process (server rule 22). Pods of release 0 read and write while migration jobs apply the expand step
// of release 1, and restart during and after it; pods of release 1 start beside them, and each reads
// what the other wrote and one of them takes a single-use value; the contract step is applied when the
// pods of release 0 are gone; and a pod of release 0 that starts after it refuses, naming the versions.
// No round of any pod fails on the way, and no login is lost or counted twice.
func RollingMigration(t *testing.T, d Deployment) {
	t.Helper()
	ctx := context.Background()
	if version, err := d.Migrate(ctx, 0, 0, false); err != nil || version != d.Released {
		t.Fatalf("the migration job of the release: version %d, err %v", version, err)
	}
	store := d.testStore(t)
	whole := t
	olds := []*PodProcess{d.Start(t, "old-0", 0, 0, false), d.Start(t, "old-1", 1, 0, false), d.Start(t, "old-2", 2, 0, false)}
	up(t, olds...)
	serve(t, olds...)
	ask(t, olds[0], "set session:before of-before", "ok")
	ask(t, olds[1], "set code:before once", "ok")
	served(t, olds...)
	var news []*PodProcess

	t.Run("the next release's expand step is applied while the pods serve, and pods restart during and after it", func(t *testing.T) {
		const jobs = 3
		errs := make(chan error, jobs)
		for i := range jobs {
			go func() {
				version, err := d.Migrate(ctx, i, 1, false)
				if err == nil && version != d.Released+1 {
					err = fmt.Errorf("the job leaves the schema at version %d", version)
				}
				errs <- err
			}()
		}
		stopped(t, store, olds[2])
		olds[2] = d.Start(whole, "old-2-restarted-during", 2, 0, false)
		for range jobs {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		up(t, olds[2])
		serve(t, olds[2])
		if got := d.Applied(t); !slices.Equal(got, upTo(d.Released+1)) {
			t.Fatalf("the database records the steps %v", got)
		}
		stopped(t, store, olds[1])
		olds[1] = d.Start(whole, "old-1-restarted-after", 1, 0, false)
		up(t, olds[1])
		serve(t, olds[1])
		served(t, olds...)
		ask(t, olds[1], "get session:before", "value of-before")
	})

	t.Run("pods of the next release start beside them: each reads what the other wrote, and a single-use value goes to one", func(t *testing.T) {
		news = []*PodProcess{d.Start(whole, "new-0", 0, 1, false), d.Start(whole, "new-1", 1, 1, false)}
		up(t, news...)
		serve(t, news...)
		ask(t, news[0], "get session:before", "value of-before")
		ask(t, news[0], "set session:next of-next", "ok")
		ask(t, olds[0], "get session:next", "value of-next")
		answers := make(chan string, 2)
		for _, pod := range []*PodProcess{olds[2], news[1]} {
			go func() {
				answer, err := pod.Ask("take code:before")
				if err != nil {
					answer = err.Error()
				}
				answers <- answer
			}()
		}
		if got := []string{<-answers, <-answers}; !slices.Contains(got, "value once") || !slices.Contains(got, "absent") {
			t.Errorf("a pod of each release took the single-use value at once: %q", got)
		}
		served(t, append(slices.Clone(olds), news...)...)
		if version, err := d.Migrate(ctx, 0, 1, false); err != nil || version != d.Released+1 {
			t.Errorf("a job that was not told to contract: version %d, err %v", version, err)
		}
	})

	t.Run("the contract step is applied when the old pods are gone, and an old pod then refuses to start, naming the versions", func(t *testing.T) {
		if news == nil {
			t.Skip("the pods of the next release did not start")
		}
		stopped(t, store, olds...)
		if version, err := d.Migrate(ctx, 1, 1, true); err != nil || version != d.Released+2 {
			t.Fatalf("the job that contracts: version %d, err %v", version, err)
		}
		served(t, news...)
		late := d.Start(t, "old-late", 0, 0, false)
		started, version, refusal, err := late.Up()
		if err != nil {
			t.Fatal(err)
		}
		if started || !version {
			t.Fatalf("a pod of the release of before, after the contract step: up %v, a version error %v: %s", started, version, refusal)
		}
		for _, says := range []string{fmt.Sprintf("version %d", d.Released+2), fmt.Sprintf("step %d", d.Released+2), fmt.Sprintf("up to %d", d.Released)} {
			if !strings.Contains(refusal, says) {
				t.Errorf("the refusal does not say %q: %s", says, refusal)
			}
		}
		restarted := d.Start(t, "new-restarted", 2, 1, false)
		news = append(news, restarted)
		up(t, restarted)
		serve(t, restarted)
		ask(t, restarted, "get session:before", "value of-before")
		ask(t, restarted, "get session:next", "value of-next")
		ask(t, restarted, "get code:before", "absent")
		served(t, news...)
		stopped(t, store, news...)
	})
}
