package hostports

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestForwardJumpIsFirst(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "cattle first",
			out: strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -j CATTLE_FORWARD",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
			}, "\n"),
			want: true,
		},
		{
			name: "docker first",
			out: strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
				"-A FORWARD -j CATTLE_FORWARD",
			}, "\n"),
			want: false,
		},
		{
			name: "missing",
			out: strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
			}, "\n"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := forwardJumpIsFirst([]byte(tt.out)); got != tt.want {
				t.Fatalf("forwardJumpIsFirst() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnsureForwardJumpFirstReordersExistingRule(t *testing.T) {
	var commands [][]string
	deleteAttempts := 0

	w := &watcher{
		output: func(args ...string) ([]byte, error) {
			commands = append(commands, append([]string(nil), args...))
			return []byte(strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
				"-A FORWARD -j CATTLE_FORWARD",
			}, "\n")), nil
		},
		runCommand: func(args ...string) error {
			commands = append(commands, append([]string(nil), args...))
			if reflect.DeepEqual(args, []string{"iptables", "-w", "-D", "FORWARD", "-j", "CATTLE_FORWARD"}) {
				deleteAttempts++
				if deleteAttempts == 1 {
					return nil
				}
				return errors.New("not found")
			}
			return nil
		},
	}

	if err := w.ensureForwardJumpFirst("iptables"); err != nil {
		t.Fatal(err)
	}

	want := [][]string{
		{"iptables", "-w", "-S", "FORWARD"},
		{"iptables", "-w", "-D", "FORWARD", "-j", "CATTLE_FORWARD"},
		{"iptables", "-w", "-D", "FORWARD", "-j", "CATTLE_FORWARD"},
		{"iptables", "-w", "-I", "FORWARD", "1", "-j", "CATTLE_FORWARD"},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %#v, want %#v", commands, want)
	}
}

func TestEnsureForwardJumpFirstLeavesCorrectOrderAlone(t *testing.T) {
	var commands [][]string
	w := &watcher{
		output: func(args ...string) ([]byte, error) {
			commands = append(commands, append([]string(nil), args...))
			return []byte(strings.Join([]string{
				"-P FORWARD ACCEPT",
				"-A FORWARD -j CATTLE_FORWARD",
				"-A FORWARD -j DOCKER-USER",
				"-A FORWARD -j DOCKER-FORWARD",
			}, "\n")), nil
		},
		runCommand: func(args ...string) error {
			commands = append(commands, append([]string(nil), args...))
			return nil
		},
	}

	if err := w.ensureForwardJumpFirst("iptables"); err != nil {
		t.Fatal(err)
	}

	want := [][]string{{"iptables", "-w", "-S", "FORWARD"}}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %#v, want %#v", commands, want)
	}
}
