package utils

import (
	"github.com/mvdan/xurls"
	"regexp"
	"strings"
)

func ExtractDomains(content string) []string {
	domains := xurls.Strict.FindAllString(content, -1)
	cssurlregex := regexp.MustCompile(`(?i)url\((.*?)\)`)
	cssDomains := cssurlregex.FindAllString(content, -1)
	for _, cssDomain := range cssDomains {
		if strings.HasPrefix(strings.ToLower(cssDomain), "url(") {
			cssDomain = cssDomain[4 : len(cssDomain)-1]
		}
		if !strings.HasSuffix(cssDomain, ":before") && !strings.HasSuffix(cssDomain, ":after") {
			domains = append(domains, cssDomain)
		}
	}
	return domains
}

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
