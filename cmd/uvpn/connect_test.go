package main

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/howtomakeaname/univpn-cli/internal/vpn"
)

func TestReconnectBoundsAndBackoff(t *testing.T) {
	calls := 0
	var delays []time.Duration
	err := connectLoop(context.Background(), 7, func() error { calls++; return &vpn.ChannelError{Channel: "control", Err: io.EOF} }, func(_ context.Context, delay time.Duration) error { delays = append(delays, delay); return nil })
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 32 * time.Second}
	if !errors.Is(err, io.EOF) || calls != 8 || !reflect.DeepEqual(delays, want) {
		t.Fatalf("calls=%d delays=%v error=%v", calls, delays, err)
	}
	for _, invalid := range []int{-1, 11} {
		if connectLoop(context.Background(), invalid, func() error { t.Fatal("invalid retry count reached login"); return nil }, nil) == nil {
			t.Fatal("accepted invalid retry count")
		}
	}
}

func TestReconnectNeverRetriesRejection(t *testing.T) {
	for _, failure := range []error{vpn.ErrSessionRevoked, &vpn.EndpointRequirement{Check: 1}, errors.New("VPN authentication rejected"), errors.New("certificate pin mismatch")} {
		calls := 0
		err := connectLoop(context.Background(), 3, func() error { calls++; return failure }, func(context.Context, time.Duration) error { t.Fatal("backoff after rejection"); return nil })
		if calls != 1 || err != failure {
			t.Fatalf("retried rejection: calls=%d error=%v", calls, err)
		}
	}
}

func TestReconnectStopsOnFreshLoginRejection(t *testing.T) {
	failure := errors.New("fresh MFA rejected")
	calls := 0
	err := connectLoop(context.Background(), 3, func() error {
		calls++
		if calls == 1 {
			return vpn.ErrReauthenticationRequired
		}
		return failure
	}, func(context.Context, time.Duration) error { return nil })
	if calls != 2 || err != failure {
		t.Fatalf("retried credentials/MFA: calls=%d error=%v", calls, err)
	}
}

func TestReconnectCancellationClosesBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := connectLoop(ctx, 3, func() error { calls++; cancel(); return vpn.ErrReauthenticationRequired }, waitReconnect)
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancellation ignored: %v", err)
	}
	if !errors.Is(waitReconnect(ctx, time.Hour), context.Canceled) {
		t.Fatal("backoff ignored cancellation")
	}
}
