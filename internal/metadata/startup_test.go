package metadata

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDaemonWaitSurvivesMetadataReplacement(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) <= 10 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `"ready"`)
	}))
	defer server.Close()
	client, err := newHTTPClient(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	var waited time.Duration
	err = waitForConnectionContext(context.Background(), client, func(ctx context.Context, delay time.Duration) error {
		if delay > 4*time.Second {
			t.Errorf("retry delay is not bounded: %s", delay)
		}
		waited += delay // Logical time: no timing-dependent sleep in this regression.
		return nil
	})
	if err != nil || attempts.Load() != 11 || waited <= connectionDeadline {
		t.Fatalf("replacement recovery: attempts=%d waited=%s err=%v", attempts.Load(), waited, err)
	}
}

func TestDaemonWaitCancellationDuringRequest(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := NewClientAndWaitContext(ctx, server.URL)
		result <- err
	}()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("request cancellation = %v", err)
	}
}

func TestDaemonWaitCancellationBetweenAttempts(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := newHTTPClient(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = waitForConnectionContext(ctx, client, func(ctx context.Context, _ time.Duration) error {
		cancel()
		return pauseRetry(ctx, time.Hour)
	})
	if !errors.Is(err, context.Canceled) || attempts.Load() != 1 {
		t.Fatalf("cancelled wait retried: attempts=%d err=%v", attempts.Load(), err)
	}
}

func TestDaemonWaitRejectsUnsafeURLBeforeRetry(t *testing.T) {
	if _, err := NewClientAndWaitContext(context.Background(), "http://user:secret@example.test/metadata"); err == nil {
		t.Fatal("unsafe URL was accepted")
	}
}
