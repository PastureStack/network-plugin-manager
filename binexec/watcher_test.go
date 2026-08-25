package binexec

import "testing"

func TestShellQuoteKeepsMetadataInsideOneLiteral(t *testing.T) {
	input := "service'$(touch /tmp/should-not-run)"
	want := "'service'\"'\"'$(touch /tmp/should-not-run)'"
	if got := shellQuote(input); got != want {
		t.Fatalf("shellQuote() = %q, want %q", got, want)
	}
}
