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

// kvWriter writes sectioned key-value output, similar to openssl x509 -text.
// Sections have bold headers, and key-value pairs are indented under them.
type kvWriter struct {
	buf     bytes.Buffer
	tw      *tabwriter.Writer
	indent  int
	started bool // whether any section has been written
}

func newKVWriter() *kvWriter {
	kv := &kvWriter{}
	kv.tw = tabwriter.NewWriter(&kv.buf, 0, 0, 2, ' ', 0)
	return kv
}

// Section writes a section header and increases indent for subsequent KV/Line calls.
func (kv *kvWriter) Section(title string) {
	kv.tw.Flush()
	if kv.started {
		kv.buf.WriteByte('\n')
	}
	kv.started = true
	prefix := strings.Repeat("    ", kv.indent)
	if isTerminal() {
		kv.buf.WriteString(prefix + ansiBold + title + ":" + ansiReset + "\n")
	} else {
		kv.buf.WriteString(prefix + title + ":\n")
	}
	kv.indent++
	// Reset tabwriter for the new section so columns align within section
	kv.tw = tabwriter.NewWriter(&kv.buf, 0, 0, 2, ' ', 0)
}

// EndSection decreases indent level.
func (kv *kvWriter) EndSection() {
	kv.tw.Flush()
	if kv.indent > 0 {
		kv.indent--
	}
	kv.tw = tabwriter.NewWriter(&kv.buf, 0, 0, 2, ' ', 0)
}

// KV writes an indented key-value pair.
func (kv *kvWriter) KV(key, value string) {
	prefix := strings.Repeat("    ", kv.indent)
	if isTerminal() {
		fmt.Fprintf(kv.tw, "%s%s%s%s\t%s\n", prefix, ansiBold, key, ansiReset, value)
	} else {
		fmt.Fprintf(kv.tw, "%s%s\t%s\n", prefix, key, value)
	}
}

// Line writes an indented plain line (no key-value formatting).
func (kv *kvWriter) Line(text string) {
	kv.tw.Flush()
	prefix := strings.Repeat("    ", kv.indent)
	kv.buf.WriteString(prefix + text + "\n")
}

// String returns the formatted output.
func (kv *kvWriter) String() string {
	kv.tw.Flush()
	return kv.buf.String()
}

// Print writes the formatted output to stdout.
func (kv *kvWriter) Print() error {
	_, err := fmt.Print(kv.String())
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

// colonHex formats a byte slice as colon-separated hex (like openssl fingerprints).
func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
