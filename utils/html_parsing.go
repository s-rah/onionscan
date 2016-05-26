package utils

import "golang.org/x/net/html"

func GetAttribute(tag html.Token, name string) string {
	for _, a := range tag.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}
