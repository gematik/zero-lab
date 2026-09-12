package common

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrNoTerminal is returned by AskYesNo when there is no controlling terminal
// to ask on — the caller decides whether that means "refuse" or "assume yes".
var ErrNoTerminal = errors.New("no terminal to ask on")

// AskYesNo prints prompt on stderr and reads one line from the controlling
// terminal, not stdin or stdout, so a command whose stdout is a pipe can
// still ask. Only "y"/"yes" (any case) means yes.
func AskYesNo(prompt string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, ErrNoTerminal
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return false, fmt.Errorf("reading answer: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// Spinner is an animated waiting indicator on stderr; silent when stderr is
// not a terminal.
type Spinner struct {
	msg  string
	stop chan struct{}
	done sync.WaitGroup
}

// StartSpinner shows msg with a spinner until Stop is called.
func StartSpinner(msg string) *Spinner {
	s := &Spinner{msg: msg, stop: make(chan struct{})}
	if !IsTerminal() {
		return s
	}
	s.done.Go(func() {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			case <-ticker.C:
				fmt.Fprintf(os.Stderr, "\r%s %s", frames[i%len(frames)], s.msg)
				i++
			}
		}
	})
	return s
}

// Stop clears the spinner line.
func (s *Spinner) Stop() {
	close(s.stop)
	s.done.Wait()
}

// PinResult reports a PIN operation's outcome on stderr.
func PinResult(operation string, pinResult string, leftTries int) {
	if pinResult == "OK" {
		fmt.Fprintf(os.Stderr, "✅ %s successful\n", operation)
		return
	}
	fmt.Fprintf(os.Stderr, "❌ %s failed: %s\n", operation, pinResult)
	if leftTries > 0 {
		fmt.Fprintf(os.Stderr, "   Remaining tries: %d\n", leftTries)
	}
}
