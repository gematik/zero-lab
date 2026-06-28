package brainpool_test

import (
	"fmt"
	"reflect"
	"testing"
)

// Minimal, dependency-free test assertions covering the subset previously taken
// from testify. They are non-fatal (like testify's assert.*): a failure is
// reported and the test continues.

func msgf(msg []any) string {
	if len(msg) == 0 {
		return ""
	}
	if s, ok := msg[0].(string); ok {
		return ": " + fmt.Sprintf(s, msg[1:]...)
	}
	return ": " + fmt.Sprint(msg...)
}

func assertEqual(t *testing.T, expected, actual any, msg ...any) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expected %v, got %v%s", expected, actual, msgf(msg))
	}
}

func assertNotEqual(t *testing.T, a, b any, msg ...any) {
	t.Helper()
	if reflect.DeepEqual(a, b) {
		t.Errorf("expected values to differ, both %v%s", a, msgf(msg))
	}
}

func assertTrue(t *testing.T, cond bool, msg ...any) {
	t.Helper()
	if !cond {
		t.Errorf("expected true%s", msgf(msg))
	}
}

func assertFalse(t *testing.T, cond bool, msg ...any) {
	t.Helper()
	if cond {
		t.Errorf("expected false%s", msgf(msg))
	}
}

func assertNoError(t *testing.T, err error, msg ...any) {
	t.Helper()
	if err != nil {
		t.Errorf("unexpected error: %v%s", err, msgf(msg))
	}
}

func assertNotNil(t *testing.T, obj any, msg ...any) {
	t.Helper()
	if isNil(obj) {
		t.Errorf("expected non-nil%s", msgf(msg))
	}
}

func assertNotEmpty(t *testing.T, obj any, msg ...any) {
	t.Helper()
	if length(obj) == 0 {
		t.Errorf("expected non-empty%s", msgf(msg))
	}
}

func assertEmpty(t *testing.T, obj any, msg ...any) {
	t.Helper()
	if length(obj) != 0 {
		t.Errorf("expected empty, got %v%s", obj, msgf(msg))
	}
}

func assertGreater(t *testing.T, a, b any, msg ...any) {
	t.Helper()
	if toInt64(a) <= toInt64(b) {
		t.Errorf("expected %v > %v%s", a, b, msgf(msg))
	}
}

func assertLessOrEqual(t *testing.T, a, b any, msg ...any) {
	t.Helper()
	if toInt64(a) > toInt64(b) {
		t.Errorf("expected %v <= %v%s", a, b, msgf(msg))
	}
}

func assertContains(t *testing.T, container, element any, msg ...any) {
	t.Helper()
	cv := reflect.ValueOf(container)
	if cv.Kind() != reflect.Slice && cv.Kind() != reflect.Array {
		t.Errorf("Contains: container is not a slice/array%s", msgf(msg))
		return
	}
	for i := 0; i < cv.Len(); i++ {
		if reflect.DeepEqual(cv.Index(i).Interface(), element) {
			return
		}
	}
	t.Errorf("expected container to contain %v%s", element, msgf(msg))
}

func isNil(obj any) bool {
	if obj == nil {
		return true
	}
	v := reflect.ValueOf(obj)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Slice, reflect.Map, reflect.Chan, reflect.Func:
		return v.IsNil()
	default:
		return false
	}
}

func length(obj any) int {
	if obj == nil {
		return 0
	}
	v := reflect.ValueOf(obj)
	switch v.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map, reflect.String, reflect.Chan:
		return v.Len()
	default:
		if isNil(obj) {
			return 0
		}
		return 1
	}
}

func toInt64(v any) int64 {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(rv.Uint())
	default:
		panic(fmt.Sprintf("not an integer: %T", v))
	}
}
