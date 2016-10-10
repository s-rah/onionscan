package config

import (
	"encoding/json"
	"io/ioutil"
)

type CrawlConfig struct {
	Onion   string   `json:"onion"`
	Base    string   `json:"base"`
	Exclude []string `json:"exclude"`
}

func LoadCrawlConfig(filename string) (CrawlConfig, error) {
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		return CrawlConfig{}, err
	}
	res := CrawlConfig{}
	err = json.Unmarshal(dat, &res)
	return res, err
}
