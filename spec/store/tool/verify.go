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

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"
)

// The adapter protocol: the verifier writes one request per line to the adapter's standard
// input and reads one response per line from its standard output, in order.
//
//	request:  {"id": "...", "kind": "...", "input": {...}}
//	response: {"id": "...", "code": "...", "output": {...}}
//
// An adapter answers "unsupported" for a kind or backend it does not implement.

type request struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Input obj    `json:"input"`
}

type response struct {
	ID     string `json:"id"`
	Code   string `json:"code"`
	Output obj    `json:"output,omitempty"`
}

const unsupported = "unsupported"

const maxLine = 64 << 20

// serve answers requests with the reference, so that the verifier can be checked and an
// adapter's author can compare answers line by line.
func serve(in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), maxLine)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		var req request
		o, err := decodeObj(sc.Bytes())
		if err == nil {
			err = remarshal(o, &req)
		}
		if err != nil {
			return fmt.Errorf("request: %w", err)
		}
		if req.Input, err = normalize(req.Input); err != nil {
			return err
		}
		c, output, err := evaluate(req.Kind, req.Input)
		resp := response{ID: req.ID, Code: string(c), Output: output}
		if errors.Is(err, errBadCase) {
			resp = response{ID: req.ID, Code: unsupported}
		} else if err != nil {
			return fmt.Errorf("%s: %w", req.ID, err)
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func remarshal(from any, to any) error {
	b, err := json.Marshal(from)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, to)
}

type outcome struct {
	id, verdict, detail string
}

func verify(path string, command []string, timeout time.Duration, strict bool, markdown, name string) error {
	m, err := readManifest(path)
	if err != nil {
		return err
	}
	outcomes, err := runAdapter(m, command, timeout)
	if err != nil {
		return err
	}
	var pass, fail, skip int
	for _, o := range outcomes {
		switch o.verdict {
		case "pass":
			pass++
		case "skip":
			skip++
			fmt.Printf("SKIP %s\n", o.id)
		default:
			fail++
			fmt.Printf("FAIL %s: %s\n", o.id, o.detail)
		}
	}
	fmt.Printf("%d passed, %d failed, %d not supported by the adapter, of %d\n", pass, fail, skip, len(outcomes))
	if markdown != "" {
		if err := appendMarkdown(markdown, name, outcomes); err != nil {
			return err
		}
	}
	if fail > 0 || (strict && skip > 0) {
		return fmt.Errorf("not conformant")
	}
	return nil
}

func runAdapter(m manifest, command []string, timeout time.Duration) ([]outcome, error) {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	lines := make(chan []byte)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 1<<20), maxLine)
		for sc.Scan() {
			lines <- append([]byte(nil), sc.Bytes()...)
		}
		close(lines)
	}()

	enc := json.NewEncoder(stdin)
	var outcomes []outcome
	for _, c := range m.Cases {
		if err := enc.Encode(request{ID: c.ID, Kind: c.Kind, Input: c.Input}); err != nil {
			return nil, fmt.Errorf("%s: writing to the adapter: %w", c.ID, err)
		}
		var line []byte
		select {
		case l, ok := <-lines:
			if !ok {
				return nil, fmt.Errorf("%s: the adapter closed its output", c.ID)
			}
			line = l
		case <-time.After(timeout):
			return nil, fmt.Errorf("%s: no answer within %s", c.ID, timeout)
		}
		outcomes = append(outcomes, judge(c, line))
	}
	return outcomes, nil
}

func judge(c manifestCase, line []byte) outcome {
	o, err := decodeObj(line)
	var resp response
	if err == nil {
		err = remarshal(o, &resp)
	}
	if err != nil {
		return outcome{c.ID, "fail", "unreadable answer: " + err.Error()}
	}
	if resp.ID != c.ID {
		return outcome{c.ID, "fail", fmt.Sprintf("answer for %q", resp.ID)}
	}
	if resp.Code == unsupported {
		return outcome{c.ID, "skip", ""}
	}
	if resp.Code != c.Expect.Code {
		return outcome{c.ID, "fail", fmt.Sprintf("code %s, want %s", resp.Code, c.Expect.Code)}
	}
	if c.Expect.Code == string(codeOK) {
		got, err := normalize(resp.Output)
		if err != nil {
			return outcome{c.ID, "fail", err.Error()}
		}
		want := c.Expect.Output
		if want == nil {
			want = obj{}
		}
		if got == nil {
			got = obj{}
		}
		if !reflect.DeepEqual(got, want) {
			return outcome{c.ID, "fail", "output differs: " + firstDifference(want, got)}
		}
	}
	return outcome{c.ID, "pass", ""}
}

func firstDifference(want, got any) string {
	w, _ := json.Marshal(want)
	g, _ := json.Marshal(got)
	ws, gs := string(w), string(g)
	i := 0
	for i < len(ws) && i < len(gs) && ws[i] == gs[i] {
		i++
	}
	from := max(i-40, 0)
	return fmt.Sprintf("want …%s…, got …%s…", clip(ws[from:], 100), clip(gs[from:], 100))
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// appendMarkdown adds one column per implementation in the shape of spec/pkcs12's matrix.
func appendMarkdown(path, name string, outcomes []outcome) error {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s\n\n| Case | Result |\n|---|---|\n", name)
	for _, o := range outcomes {
		fmt.Fprintf(&b, "| %s | %s |\n", o.id, o.verdict)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
