// based on https://dusted.codes/creating-a-pretty-console-logger-using-gos-slog-package
package prettylog

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strconv"
)

const (
	timeFormat = "15:04:05.000"
)

const (
	reset = "\033[0m"

	black        = 30
	red          = 31
	green        = 32
	yellow       = 33
	blue         = 34
	magenta      = 35
	cyan         = 36
	lightGray    = 37
	darkGray     = 90
	lightRed     = 91
	lightGreen   = 92
	lightYellow  = 93
	lightBlue    = 94
	lightMagenta = 95
	lightCyan    = 96
	white        = 97
)

func colorize(colorCode int, v string) string {
	return fmt.Sprintf("\033[%sm%s%s", strconv.Itoa(colorCode), v, reset)
}

type handler struct {
	Level  slog.Level
	Output *os.File
}

func NewHandler(level slog.Level) slog.Handler {
	return &handler{
		Level:  level,
		Output: os.Stderr,
	}
}

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.Level
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *handler) WithGroup(name string) slog.Handler {
	return h
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level < h.Level {
		return nil
	}

	level := r.Level.String() + ":"

	switch r.Level {
	case slog.LevelDebug:
		level = colorize(darkGray, level)
	case slog.LevelInfo:
		level = colorize(cyan, level)
	case slog.LevelWarn:
		level = colorize(yellow, level)
	case slog.LevelError:
		level = colorize(lightRed, level)
	}

	h.Output.WriteString(
		colorize(darkGray, r.Time.Format(timeFormat)),
	)

	h.Output.WriteString(" ")
	h.Output.WriteString(level)
	h.Output.WriteString(" ")
	h.Output.WriteString(colorize(white, r.Message))
	h.Output.WriteString(" ")

	attrs := make(map[string]any)
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})

	h.Output.WriteString(colorize(darkGray, h.attributesToString(attrs)))

	h.Output.WriteString("\n")

	return nil
}

func (h *handler) attributesToString(attrs map[string]any) string {
	for k, v := range attrs {
		if err, ok := v.(error); ok {
			attrs[k] = err.Error()
			continue
		}
		v = convert(v)
		_, err := json.Marshal(v)
		if err != nil {
			fmt.Println(err)
			attrs[k] = fmt.Sprintf("%v", v)
		} else {
			attrs[k] = v
		}

	}

	asJson, err := json.MarshalIndent(attrs, "  ", "  ")
	if err != nil {
		return fmt.Sprintf("%v", attrs)
	}
	return string(asJson)
}

type Loggable interface {
	ToLog() any
}

var customConverters = map[reflect.Type]func(any) any{
	reflect.TypeOf([]byte(nil)): func(value any) any {
		return fmt.Sprintf("%v", value)
	},
	reflect.TypeOf(Loggable(nil)): func(value any) any {
		return value.(Loggable).ToLog()
	},
}

func convert(value any) any {
	if value == nil {
		return "nil"
	}

	if converter, ok := customConverters[reflect.TypeOf(value)]; ok {
		return converter(value)
	}

	return value
}
