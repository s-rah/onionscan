package onionscan

import (
	"errors"
	"fmt"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"strings"
)

// Pipeline is a construct for managing a set of crawls, analysis and output sinks
type Pipeline struct {
	Steps   []PipelineStep
	Reports chan *report.OnionScanReport
}

// PipelineStep is an interface that functions can use to declare themselves
// as a pipeline step
type PipelineStep interface {
	Do(*report.OnionScanReport) error
}

// Init sets up a pipeline, reporting all results on the given channel
func (p *Pipeline) Init(reportChannel chan *report.OnionScanReport) {
	p.Reports = reportChannel
}

// AddStep adds a new step to the pipeline.
func (p *Pipeline) AddStep(step PipelineStep) {
	p.Steps = append(p.Steps, step)
}

// Execute takes a hidden service address and puts it through the configured
// pipeline.
func (p *Pipeline) Execute(hiddenService string) {

	// Remove Extra Prefix
	hiddenService = utils.WithoutProtocol(hiddenService)

	if strings.HasSuffix(hiddenService, "/") {
		hiddenService = hiddenService[0 : len(hiddenService)-1]
	}

	r := report.NewOnionScanReport(hiddenService)
	if utils.IsOnion(hiddenService) {

		for _, step := range p.Steps {
			err := step.Do(r)
			if err != nil {
				break
			}
		}

		// Output Report
		p.Reports <- r
	} else {
		r.Error = errors.New(fmt.Sprintf("Unknown hidden service type: %v", hiddenService))
		p.Reports <- r
	}
}
