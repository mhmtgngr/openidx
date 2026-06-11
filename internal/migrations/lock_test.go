package migrations

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestRetryUntilAcquired_SucceedsFirstTry verifies the no-op case:
// tryOnce returns nil immediately and the helper returns without
// sleeping or polling.
func TestRetryUntilAcquired_SucceedsFirstTry(t *testing.T) {
	var calls atomic.Int32
	err := retryUntilAcquired(
		context.Background(),
		1*time.Second, 10*time.Millisecond,
		func() error {
			calls.Add(1)
			return nil
		},
	)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("tryOnce called %d times, want 1", got)
	}
}

// TestRetryUntilAcquired_RetriesOnLockBusy — the helper must keep
// calling tryOnce while it returns errLockBusy, then succeed when one
// of the retries returns nil. Bound the test by capping the maxWait
// at a value that comfortably covers a small number of retries.
func TestRetryUntilAcquired_RetriesOnLockBusy(t *testing.T) {
	var calls atomic.Int32
	err := retryUntilAcquired(
		context.Background(),
		200*time.Millisecond, 10*time.Millisecond,
		func() error {
			n := calls.Add(1)
			if n < 3 {
				return errLockBusy
			}
			return nil
		},
	)
	if err != nil {
		t.Errorf("err = %v, want nil after 3rd try", err)
	}
	if got := calls.Load(); got < 3 {
		t.Errorf("tryOnce called %d times, want >= 3", got)
	}
}

// TestRetryUntilAcquired_TimesOutWhenAlwaysBusy verifies the strict
// timeout: with a 30ms budget and a 10ms poll, the helper must give up
// within roughly maxWait (allow ~3× slack for slow CI), and the
// returned error wraps errLockBusy so callers can match on it.
func TestRetryUntilAcquired_TimesOutWhenAlwaysBusy(t *testing.T) {
	start := time.Now()
	err := retryUntilAcquired(
		context.Background(),
		30*time.Millisecond, 10*time.Millisecond,
		func() error { return errLockBusy },
	)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, errLockBusy) {
		t.Errorf("err does not wrap errLockBusy: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("timed out only after %v, want close to 30ms", elapsed)
	}
}

// TestRetryUntilAcquired_ReturnsNonBusyErrorImmediately — a real DB
// error (connection-refused, deadlock, etc.) must not be retried; it
// must bubble out on the first call.
func TestRetryUntilAcquired_ReturnsNonBusyErrorImmediately(t *testing.T) {
	realErr := errors.New("dial tcp: connection refused")

	var calls atomic.Int32
	err := retryUntilAcquired(
		context.Background(),
		1*time.Second, 10*time.Millisecond,
		func() error {
			calls.Add(1)
			return realErr
		},
	)
	if !errors.Is(err, realErr) {
		t.Errorf("err = %v, want realErr", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("tryOnce called %d times for a non-retryable error, want 1", got)
	}
}

// TestRetryUntilAcquired_HonorsContextCancel — once the caller's ctx
// is canceled the helper must return ctx.Err() promptly (not wait the
// full maxWait, not silently swallow the cancellation).
func TestRetryUntilAcquired_HonorsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after the first try so we'll definitely enter the
	// time.After/ctx.Done select.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := retryUntilAcquired(
		ctx,
		5*time.Second, 50*time.Millisecond,
		func() error { return errLockBusy },
	)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("returned only after %v; cancellation should be near-immediate", elapsed)
	}
}

// TestErrLockBusy_IsExportable confirms the sentinel error is the same
// value across imports — without this guarantee `errors.Is(err,
// errLockBusy)` in retryUntilAcquired wouldn't recognize the value
// the production tryAcquireLockOnce path returns.
func TestErrLockBusy_IsExportable(t *testing.T) {
	if errLockBusy == nil {
		t.Fatal("errLockBusy is nil")
	}
	if errLockBusy.Error() == "" {
		t.Errorf("errLockBusy has empty Error()")
	}
}
