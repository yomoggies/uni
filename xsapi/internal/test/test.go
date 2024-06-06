package test

import (
	"context"
	"errors"
	"strings"
	"time"
)

func Try[T any](attempts int, interval time.Duration, f func(attempts int) (T, error)) (t T, last error) {
	for i := 0; i < attempts; i++ {
		if t, last = f(i); last == nil || Expect(last, context.Canceled, context.DeadlineExceeded) {
			break
		}
		time.Sleep(interval)
	}
	return t, last
}

func Expect(err error, expected ...error) bool {
	for _, expect := range expected {
		if errors.Is(err, expect) {
			return true
		}
		// Solution for some errors that doesn't wrap an actual error in context (e.g. fmt.Errorf("%s", err))
		if strings.Contains(err.Error(), expect.Error()) {
			return true
		}
	}
	return false
}
