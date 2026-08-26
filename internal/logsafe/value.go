// Package logsafe provides single-record formatting for external log values.
package logsafe

import (
	"fmt"
	"strings"
)

func Value(value interface{}) string {
	text := fmt.Sprint(value)
	text = strings.ReplaceAll(text, "\r", "")
	return strings.ReplaceAll(text, "\n", " ")
}
