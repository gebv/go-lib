package verify

import "testing"

func Test_normalHex(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{},
		{"abc", "abc"},
		{"7E:12:49:9C:EC:EC:22:DE:53:78:71:79:BF:28:D4:51:2D:66:23:96", "7e12499cecec22de53787179bf28d4512d662396"},
		{"7E12499CECEC22DE53787179BF28D4512D662396", "7e12499cecec22de53787179bf28d4512d662396"},
		{"7e12499cecec22de53787179bf28d4512d662396", "7e12499cecec22de53787179bf28d4512d662396"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalHex(tt.in); got != tt.want {
				t.Errorf("normalHex() = %v, want %v", got, tt.want)
			}
		})
	}
}
