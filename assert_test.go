package noise

import (
	"fmt"
	"reflect"
	"testing"
)

// C is a minimal stand-in for the gocheck API that noise_test.go was written
// against, so the package needs no third-party test dependency.
type C struct{ *testing.T }

// Checker reports whether obtained satisfies the check against args.
type Checker func(obtained interface{}, args ...interface{}) bool

// Assert stops the test when the checker fails.
func (c *C) Assert(obtained interface{}, check Checker, args ...interface{}) {
	c.Helper()
	if !check(obtained, args...) {
		c.Fatalf("assertion failed: obtained %s, args %s", describe(obtained), describe(args))
	}
}

func describe(v interface{}) string { return fmt.Sprintf("%#v", v) }

// Equals compares with ==, like gocheck.
func Equals(obtained interface{}, args ...interface{}) bool { return obtained == args[0] }

// DeepEquals compares with reflect.DeepEqual.
func DeepEquals(obtained interface{}, args ...interface{}) bool {
	return reflect.DeepEqual(obtained, args[0])
}

// HasLen checks the length of a slice, array, string, map or channel.
func HasLen(obtained interface{}, args ...interface{}) bool {
	v := reflect.ValueOf(obtained)
	switch v.Kind() {
	case reflect.Slice, reflect.Array, reflect.String, reflect.Map, reflect.Chan:
		return v.Len() == args[0].(int)
	}
	return false
}

// IsNil accepts an untyped nil or a nil pointer, slice, map, channel, function or interface.
func IsNil(obtained interface{}, _ ...interface{}) bool {
	if obtained == nil {
		return true
	}
	v := reflect.ValueOf(obtained)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// NotNil is the negation of IsNil.
func NotNil(obtained interface{}, args ...interface{}) bool { return !IsNil(obtained, args...) }

// Not negates a checker.
func Not(check Checker) Checker {
	return func(obtained interface{}, args ...interface{}) bool { return !check(obtained, args...) }
}
