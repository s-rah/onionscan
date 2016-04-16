package utils

import "github.com/mvdan/xurls"

func ExtractDomains(content string) []string {
	return xurls.Strict.FindAllString(content, -1)
}
