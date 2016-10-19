package spider

import (
	"bytes"
	"github.com/s-rah/onionscan/model"
	"github.com/s-rah/onionscan/utils"
	"golang.org/x/net/html"
	"io"
	"net/url"
	"strings"
)

func NormalizeURI(uri string, base *url.URL) string {

	if strings.HasPrefix("data:", uri) {
		return "[embedded document]"
	}

	ref, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	res := base.ResolveReference(ref)
	return res.String()
}

func SnapshotResource(response io.Reader) model.Page {
	page := model.Page{}
	buf := make([]byte, 1024*512) // Read Max 0.5 MB
	n, _ := io.ReadFull(response, buf)
	page.Snapshot = string(buf[0:n])
	return page
}

func SnapshotBinaryResource(response io.Reader) model.Page {
	page := model.Page{}
	buf := make([]byte, 1024*512) // Read Max 0.5 MB
	n, _ := io.ReadFull(response, buf)
	page.Raw = buf[0:n]
	return page
}

func ParsePage(response io.Reader, base *url.URL, snapshot bool) model.Page {

	page := model.Page{}

	if snapshot {
		buf := make([]byte, 1024*512) // Read Max 0.5 MB
		n, _ := io.ReadFull(response, buf)
		page.Snapshot = string(buf[0:n])
		response = bytes.NewReader(buf[0:n])
	}

	z := html.NewTokenizer(response)

	activeForm := model.Form{}
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		t := z.Token()

		if t.Data == "title" && tt == html.StartTagToken {
			tt := z.Next()
			if tt == html.TextToken {
				page.Title = string(z.Raw())
			}

			continue
		}

		if t.Data == "form" && tt == html.StartTagToken {
			if activeForm.Action != "" {
				page.Forms = append(page.Forms, activeForm)
			}
			activeForm = model.Form{}
			activeForm.Action = NormalizeURI(utils.GetAttribute(t, "action"), base)
		}

		if t.Data == "input" {
			field := model.Field{}
			field.Name = utils.GetAttribute(t, "name")
			field.Type = utils.GetAttribute(t, "type")
			activeForm.Fields = append(activeForm.Fields, field)
		}

		if t.Data == "img" {
			element := model.Element{}
			element.Target = NormalizeURI(utils.GetAttribute(t, "src"), base)
			element.Class = utils.GetAttribute(t, "class")
			element.Title = utils.GetAttribute(t, "alt")
			page.Images = append(page.Images, element)
		}

		if t.Data == "a" && (tt == html.StartTagToken || tt == html.SelfClosingTagToken) {
			element := model.Element{}
			element.Target = NormalizeURI(utils.GetAttribute(t, "href"), base)
			element.Class = utils.GetAttribute(t, "class")
			element.Title = utils.GetAttribute(t, "title")

			tt := z.Next()
			if tt == html.TextToken {
				element.Text = string(z.Raw())
			}

			page.Anchors = append(page.Anchors, element)

			continue

		}

		if t.Data == "link" && (tt == html.StartTagToken || tt == html.SelfClosingTagToken) {
			element := model.Element{}
			element.Target = NormalizeURI(utils.GetAttribute(t, "href"), base)
			element.Class = utils.GetAttribute(t, "rel")
			element.Title = utils.GetAttribute(t, "type")
			page.Links = append(page.Links, element)
		}

		if t.Data == "script" && (tt == html.StartTagToken || tt == html.SelfClosingTagToken) {
			element := model.Element{}
			element.Target = NormalizeURI(utils.GetAttribute(t, "src"), base)
			element.Class = utils.GetAttribute(t, "type")
			page.Scripts = append(page.Scripts, element)
		}

	}

	if activeForm.Action != "" {
		page.Forms = append(page.Forms, activeForm)
	}

	return page
}
