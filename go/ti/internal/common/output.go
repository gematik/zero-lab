package common

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/alecthomas/chroma/v2/quick"
)

const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
)

// OutputFlag is the shared -o/--output format selector ("text" or "json"),
// bound by the command groups that expose it and read by their leaf commands.
var OutputFlag string

// IsTerminal reports whether stdout is a character device (a terminal),
// used to decide on ANSI colorization and syntax highlighting.
func IsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// PrintJSON marshals v as indented JSON, syntax-highlighted on a terminal.
func PrintJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	s := string(data) + "\n"
	if IsTerminal() {
		return quick.Highlight(os.Stdout, s, "json", "terminal256", "monokai")
	}
	fmt.Print(s)
	return nil
}

// PrintTable renders rows as a table with a bold header line when on a terminal.
func PrintTable(header string, fn func(w io.Writer)) error {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, header)
	fn(w)
	w.Flush()

	output := buf.String()
	if IsTerminal() {
		output = colorizeHeader(output)
	}
	_, err := fmt.Print(output)
	return err
}

// PrintKeyValue renders key-value pairs with bold labels when on a terminal.
func PrintKeyValue(fn func(w io.Writer)) error {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fn(w)
	w.Flush()

	output := buf.String()
	if IsTerminal() {
		output = colorizeLabels(output)
	}
	_, err := fmt.Print(output)
	return err
}

// KVWriter writes sectioned key-value output, similar to openssl x509 -text.
// Sections have bold headers, and key-value pairs are indented under them.
type KVWriter struct {
	buf     bytes.Buffer
	tw      *tabwriter.Writer
	indent  int
	started bool // whether any section has been written
}

func NewKVWriter() *KVWriter {
	kv := &KVWriter{}
	kv.tw = tabwriter.NewWriter(&kv.buf, 0, 0, 2, ' ', 0)
	return kv
}

// Section writes a section header and increases indent for subsequent KV/Line calls.
func (kv *KVWriter) Section(title string) {
	kv.tw.Flush()
	if kv.started {
		kv.buf.WriteByte('\n')
	}
	kv.started = true
	prefix := strings.Repeat("    ", kv.indent)
	if IsTerminal() {
		kv.buf.WriteString(prefix + ansiBold + title + ":" + ansiReset + "\n")
	} else {
		kv.buf.WriteString(prefix + title + ":\n")
	}
	kv.indent++
	// Reset tabwriter for the new section so columns align within section
	kv.tw = tabwriter.NewWriter(&kv.buf, 0, 0, 2, ' ', 0)
}

// EndSection decreases indent level.
func (kv *KVWriter) EndSection() {
	kv.tw.Flush()
	if kv.indent > 0 {
		kv.indent--
	}
	kv.tw = tabwriter.NewWriter(&kv.buf, 0, 0, 2, ' ', 0)
}

// KV writes an indented key-value pair.
func (kv *KVWriter) KV(key, value string) {
	prefix := strings.Repeat("    ", kv.indent)
	if IsTerminal() {
		fmt.Fprintf(kv.tw, "%s%s%s%s\t%s\n", prefix, ansiBold, key, ansiReset, value)
	} else {
		fmt.Fprintf(kv.tw, "%s%s\t%s\n", prefix, key, value)
	}
}

// Line writes an indented plain line (no key-value formatting).
func (kv *KVWriter) Line(text string) {
	kv.tw.Flush()
	prefix := strings.Repeat("    ", kv.indent)
	kv.buf.WriteString(prefix + text + "\n")
}

// String returns the formatted output.
func (kv *KVWriter) String() string {
	kv.tw.Flush()
	return kv.buf.String()
}

// Print writes the formatted output to stdout.
func (kv *KVWriter) Print() error {
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

// SectionHeader formats s as a bold string when on a terminal.
func SectionHeader(s string) string {
	if IsTerminal() {
		return ansiBold + s + ansiReset
	}
	return s
}

// ColonHex formats a byte slice as colon-separated hex (like openssl fingerprints).
func ColonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

// IndentXML pretty-prints XML with two-space indentation.
func IndentXML(data []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var buf bytes.Buffer
	encoder := xml.NewEncoder(&buf)
	encoder.Indent("", "  ")

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if err := encoder.EncodeToken(token); err != nil {
			return "", err
		}
	}
	if err := encoder.Flush(); err != nil {
		return "", err
	}
	buf.WriteByte('\n')
	return buf.String(), nil
}
