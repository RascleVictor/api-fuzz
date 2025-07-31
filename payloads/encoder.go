package payloads

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

func EncodePayload(payload string, method string) string {
	switch strings.ToLower(string(method)) {
	case "url":
		return url.QueryEscape(payload)
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(payload))
	case "doubleurl":
		return url.QueryEscape(url.QueryEscape(payload))
	case "hex":
		return toHex(payload)
	default:
		return payload // brut / none
	}
}

func toHex(input string) string {
	result := ""
	for _, c := range input {
		result += fmt.Sprintf("\\x%02x", c)
	}
	return result
}
