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

package ti

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

const probeReportJSON = `{"schema":1,"environment":"dev","duration_ms":3083,
	"counts":{"ok":1,"warn":0,"fail":1},
	"access_paths":[{"access":"ti-vpn","available":false,"probes":1},{"access":"internet","available":true,"probes":1}],
	"probes":[
		{"name":"idpd-ti","access":"ti-vpn","kind":"oidc","url":"https://idp.example/","host":"idp.example","source":"builtin","status":"fail","answered":false,"detail":"timeout","http_status":null,"duration_ms":3000},
		{"name":"catalog","access":"internet","kind":"catalog","url":"https://cat.example/","host":"cat.example","source":"builtin","status":"ok","answered":true,"detail":"200","http_status":200,"duration_ms":40}
	]}`

// runnerFunc lets a test decide what each run answers.
type runnerFunc func(ctx context.Context, args ...string) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, _ []byte, args ...string) ([]byte, error) {
	return f(ctx, args...)
}

func TestProbeWithFailingServicesStillReturnsItsReport(t *testing.T) {
	var asked []string
	runner := runnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
		asked = args
		return nil, &Error{ExitCode: 1, Stdout: []byte(probeReportJSON)}
	})

	report, err := Probe(context.Background(), runner, "dev")
	if err != nil {
		t.Fatalf("exit 1 with a report is a result: %v", err)
	}
	if len(asked) != 2 || asked[0] != "probe" || asked[1] != "dev" {
		t.Errorf("ran %v, want probe dev", asked)
	}
	if report.Environment != "dev" || report.Counts.OK != 1 || report.Counts.Fail != 1 {
		t.Errorf("report %+v", report)
	}
	if len(report.AccessPaths) != 2 || report.AccessPaths[0].Access != "ti-vpn" || report.AccessPaths[0].Available {
		t.Errorf("access paths %+v", report.AccessPaths)
	}
	if len(report.Probes) != 2 {
		t.Fatalf("probes %+v", report.Probes)
	}
	got := report.Probes[0]
	if got.Name != "idpd-ti" || got.Access != "ti-vpn" || got.Status != "fail" || got.Detail != "timeout" {
		t.Errorf("probe %+v", got)
	}
}

func TestProbeFailureWithoutReportIsAnError(t *testing.T) {
	want := &Error{ExitCode: 2, Kind: "environment_invalid", Message: "no such environment"}
	runner := runnerFunc(func(context.Context, ...string) ([]byte, error) { return nil, want })

	_, err := Probe(context.Background(), runner, "dev")
	var got *Error
	if !errors.As(err, &got) || got != want {
		t.Fatalf("err = %v, want the tool's error", err)
	}
}

func TestProbeRefusesAReportOfAnotherSchemaVersion(t *testing.T) {
	other := []byte(`{"schema":2,"environment":"dev"}`)
	for name, runner := range map[string]Runner{
		"exit 0": runnerFunc(func(context.Context, ...string) ([]byte, error) { return other, nil }),
		"exit 1": runnerFunc(func(context.Context, ...string) ([]byte, error) {
			return nil, &Error{ExitCode: 1, Stdout: other}
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if report, err := Probe(context.Background(), runner, "dev"); err == nil {
				t.Fatalf("accepted %+v", report)
			}
		})
	}
}

func TestProberCallersShareOneRunPerEnvironment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var runs atomic.Int32
		runner := runnerFunc(func(context.Context, ...string) ([]byte, error) {
			runs.Add(1)
			time.Sleep(3 * time.Second)
			return []byte(probeReportJSON), nil
		})
		prober := NewProber(runner, time.Now)

		var wg sync.WaitGroup
		for range 10 {
			wg.Go(func() {
				if _, err := prober.Probe(t.Context(), "dev"); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if got := runs.Load(); got != 1 {
			t.Errorf("%d runs for one environment, want 1", got)
		}

		if _, err := prober.Probe(t.Context(), "ref"); err != nil {
			t.Fatal(err)
		}
		if got := runs.Load(); got != 2 {
			t.Errorf("%d runs after a second environment, want 2", got)
		}
	})
}

func TestProberReusesAResultForAMinuteThenRunsAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var runs atomic.Int32
		runner := runnerFunc(func(context.Context, ...string) ([]byte, error) {
			runs.Add(1)
			return []byte(probeReportJSON), nil
		})
		prober := NewProber(runner, time.Now)

		probe := func() {
			t.Helper()
			if _, err := prober.Probe(t.Context(), "dev"); err != nil {
				t.Fatal(err)
			}
		}
		probe()
		time.Sleep(time.Minute - time.Second)
		probe()
		if got := runs.Load(); got != 1 {
			t.Errorf("%d runs within the minute, want 1", got)
		}
		time.Sleep(time.Second)
		probe()
		if got := runs.Load(); got != 2 {
			t.Errorf("%d runs after the minute, want 2", got)
		}
	})
}

func TestProberReusesAFailedRunToo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var runs atomic.Int32
		runner := runnerFunc(func(context.Context, ...string) ([]byte, error) {
			runs.Add(1)
			return nil, errors.New("ti is gone")
		})
		prober := NewProber(runner, time.Now)

		for range 3 {
			if _, err := prober.Probe(t.Context(), "dev"); err == nil {
				t.Fatal("want the run's error")
			}
		}
		if got := runs.Load(); got != 1 {
			t.Errorf("%d runs, a failing tool must not be restarted per page load", got)
		}
	})
}

func TestProberRunOutlivesTheCallerThatStartedIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runner := runnerFunc(func(ctx context.Context, _ ...string) ([]byte, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(3 * time.Second):
				return []byte(probeReportJSON), nil
			}
		})
		prober := NewProber(runner, time.Now)

		leaving, leave := context.WithCancel(t.Context())
		first := make(chan error, 1)
		go func() {
			_, err := prober.Probe(leaving, "dev")
			first <- err
		}()
		synctest.Wait()
		leave()
		if err := <-first; !errors.Is(err, context.Canceled) {
			t.Fatalf("leaving caller: %v", err)
		}

		if _, err := prober.Probe(t.Context(), "dev"); err != nil {
			t.Fatalf("second caller shares the run and must get its result: %v", err)
		}
	})
}
