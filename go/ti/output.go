package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
)

// printTable renders rows as a table with a bold header line when on a terminal.
func printTable(header string, fn func(w io.Writer)) error {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, header)
	fn(w)
	w.Flush()

	output := buf.String()
	if isTerminal() {
		output = colorizeHeader(output)
	}
	_, err := fmt.Print(output)
	return err
}

// printKeyValue renders key-value pairs with bold labels when on a terminal.
func printKeyValue(fn func(w io.Writer)) error {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fn(w)
	w.Flush()

	output := buf.String()
	if isTerminal() {
		output = colorizeLabels(output)
	}
	_, err := fmt.Print(output)
	return err
}

func colorizeHeader(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return ansiBold + s[:idx] + ansiReset + s[idx:]
	}
	return ansiBold + s + ansiReset
}

func colorizeLabels(s string) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	var out strings.Builder
	for _, line := range lines {
		if label, rest, ok := splitAtGap(line); ok {
			out.WriteString(ansiBold)
			out.WriteString(label)
			out.WriteString(ansiReset)
			out.WriteString(rest)
		} else {
			out.WriteString(line)
		}
		out.WriteByte('\n')
	}
	return out.String()
}

// splitAtGap finds the first occurrence of 2+ consecutive spaces in a line,
// splitting it into the label part and the rest (including the gap).
func splitAtGap(line string) (label, rest string, ok bool) {
	for i := 0; i < len(line)-1; i++ {
		if line[i] == ' ' && line[i+1] == ' ' {
			return line[:i], line[i:], true
		}
	}
	return "", "", false
}

// sectionHeader formats s as a bold string when on a terminal.
func sectionHeader(s string) string {
	if isTerminal() {
		return ansiBold + s + ansiReset
	}
	return s
}
