package utils

import (
	"strings"
)

func WithoutSubdomains(urlhost string) string {
	urlParts := strings.Split(urlhost, ".")
	if len(urlParts) < 2 {
		return ""
	}
	return strings.Join(urlParts[len(urlParts)-2:], ".")
}

func WithoutProtocol(url string) string {
	if strings.HasPrefix(url, "http://") {
		return url[7:]
	}
	if strings.HasPrefix(url, "https://") {
		return url[8:]
	}
	if strings.HasPrefix(url, "//") {
		return url[2:]
	}
	return url
}
