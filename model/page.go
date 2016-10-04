package model

import (
	"net/http"
)

type Page struct {
	Status   int
	Headers  http.Header
	Title    string
	Forms    []Form
	Images   []Element
	Anchors  []Element
	Links    []Element
	Scripts  []Element
	Snapshot string
	Raw      []byte
	Hash     string
}

type Element struct {
	Target string
	Title  string
	Class  string
	Text   string
}

type Field struct {
	Name string
	Type string
}

type Form struct {
	Action string
	Fields []Field
}
