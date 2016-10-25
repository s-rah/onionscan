package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// ExtraRelationship defines additional information which can be
// extracted after an initial relationship is detected.
type ExtraRelationship struct {
	Name   string `json:"name"`
	Regex  string `json:"regex"`
	Rollup bool   `json:"rollup"`
}

// Relationship defines a section of a page that can be extract to provide a
// unique identifier relationship.
type Relationship struct {
	Name                   string              `json:"name"`
	TriggerIdentifierRegex string              `json:"triggeridentifierregex"`
	ExtraRelationships     []ExtraRelationship `json:"extrarelationships"`
}

// CrawlConfig defines user-specified options to tweak the current crawl.
type CrawlConfig struct {
	Onion         string         `json:"onion"`
	Base          string         `json:"base"`
	Exclude       []string       `json:"exclude"`
	Relationships []Relationship `json:"relationships"`
}

// GetRelationship provides a Relationship by its name.
func (cc *CrawlConfig) GetRelationship(name string) (Relationship, error) {
	for _, relationship := range cc.Relationships {
		if relationship.Name == name {
			return relationship, nil
		}
	}
	return Relationship{}, fmt.Errorf(`Could not find Relationship "%s"`, name)
}

// LoadCrawlConfig creates a CrawlConfig object by loading a given filename.
func LoadCrawlConfig(filename string) (CrawlConfig, error) {
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		return CrawlConfig{}, err
	}
	res := CrawlConfig{}
	err = json.Unmarshal(dat, &res)
	return res, err
}
