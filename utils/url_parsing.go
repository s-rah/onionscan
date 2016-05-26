package utils

import (
	"github.com/mvdan/xurls"
	"strings"
)

func ExtractDomains(content string) []string {
	return xurls.Strict.FindAllString(content, -1)
}

func WithoutSubdomains(urlhost string) string {
	urlParts := strings.Split(urlhost, ".")
	if len(urlParts) < 2 {
		return ""
	} else {
		return strings.Join(urlParts[len(urlParts)-2:], ".")
	}
}

func WithoutProtocol(url string) string {
	if strings.HasPrefix(url, "http://") {
		return url[7:]
	}
	if strings.HasPrefix(url, "https://") {
		return url[8:]
	}
	return url
}
