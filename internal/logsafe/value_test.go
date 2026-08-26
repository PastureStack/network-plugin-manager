package logsafe

import "testing"

func TestValueProducesSingleRecord(t *testing.T) {
	if got := Value("first\r\nforged\nthird"); got != "first forged third" {
		t.Fatalf("unexpected safe log value: %q", got)
	}
}
