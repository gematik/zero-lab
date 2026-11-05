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
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// proberResultLifetime bounds how often page loads reach the TI services: a page opened by
// many people, or reloaded, still causes one probe of an environment per minute.
const proberResultLifetime = time.Minute

// ProbeReport is what `ti probe` found out about an environment. It says whether the
// services answer and nothing about whether they can be trusted: the tool does not verify
// TLS for this question. Fields of the tool's report that the portal does not show, such
// as the URLs, stay out of it.
type ProbeReport struct {
	Environment string         `json:"environment"`
	DurationMS  int64          `json:"duration_ms"`
	Counts      ProbeCounts    `json:"counts"`
	AccessPaths []ProbeAccess  `json:"access_paths"`
	Probes      []ProbedTarget `json:"probes"`
}

// ProbeCounts counts the probes by status.
type ProbeCounts struct {
	OK   int `json:"ok"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// ProbeAccess is one way of reaching services. Available is false when none of its
// endpoints answered, which means the path is down rather than each service.
type ProbeAccess struct {
	Access    string `json:"access"`
	Available bool   `json:"available"`
	Probes    int    `json:"probes"`
}

// ProbedTarget is one service; Status is ok, warn or fail.
type ProbedTarget struct {
	Name       string `json:"name"`
	Access     string `json:"access"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	DurationMS int64  `json:"duration_ms"`
}

// Probe runs `ti probe env`. A service that fails makes the tool exit 1 with a full report,
// which is a result; only a run that produced no report is an error.
func Probe(ctx context.Context, runner Runner, env string) (*ProbeReport, error) {
	out, err := runner.Run(ctx, nil, "probe", env)
	if err != nil {
		var failed *Error
		if !errors.As(err, &failed) || len(failed.Stdout) == 0 {
			return nil, err
		}
		out = failed.Stdout
	}
	if err := checkSchema(out); err != nil {
		return nil, err
	}
	var report ProbeReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("reading ti probe's report: %w", err)
	}
	return &report, nil
}

// Prober shares probe runs between callers: one run per environment at a time, and its
// result, a failed run's too, for a minute.
type Prober struct {
	runner Runner
	now    func() time.Time

	mu   sync.Mutex
	runs map[string]*probeRun
}

// probeRun is one run of the tool. report and err are set before done closes; expires is
// guarded by Prober.mu and stays zero while the run is going.
type probeRun struct {
	done    chan struct{}
	report  *ProbeReport
	err     error
	expires time.Time
}

// NewProber returns a Prober that runs runner and keeps its results by the clock now.
func NewProber(runner Runner, now func() time.Time) *Prober {
	return &Prober{runner: runner, now: now, runs: make(map[string]*probeRun)}
}

// Probe returns the environment's current result, waiting for a run if there is none. A
// caller that leaves stops waiting; the run goes on for the callers sharing it, bounded by
// the runner's own timeout.
func (p *Prober) Probe(ctx context.Context, env string) (*ProbeReport, error) {
	p.mu.Lock()
	run := p.runs[env]
	if run == nil || (!run.expires.IsZero() && !p.now().Before(run.expires)) {
		run = &probeRun{done: make(chan struct{})}
		p.runs[env] = run
		go p.finish(context.WithoutCancel(ctx), run, env)
	}
	p.mu.Unlock()

	select {
	case <-run.done:
		return run.report, run.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *Prober) finish(ctx context.Context, run *probeRun, env string) {
	run.report, run.err = Probe(ctx, p.runner, env)
	p.mu.Lock()
	run.expires = p.now().Add(proberResultLifetime)
	p.mu.Unlock()
	close(run.done)
}
