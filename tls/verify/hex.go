package verify

import "strings"

func normalHex(in string) string {
	if strings.Contains(in, ":") {
		in = strings.Join(strings.Split(in, ":"), "")
	}
	return strings.ToLower(in)
}
