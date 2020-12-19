#!/bin/bash

set -e
pwd
go test -coverprofile=cover.out -v .
go test -coverprofile=config.cover.out -v ./config
go test -coverprofile=crawld.cover.out -v ./crawldb
go test -coverprofile=deanonymization.cover.out -v ./deanonymization
go test -coverprofile=model.cover.out -v ./model
go test -coverprofile=onionscan.cover.out -v ./onionscan
go test -coverprofile=protocol.cover.out -v ./protocol
go test -coverprofile=report.cover.out -v ./report
go test -coverprofile=spider.cover.out -v ./spider
go test -coverprofile=utils.cover.out -v ./utils
go test -coverprofile=webui.cover.out -v ./webui
echo "mode: set" > coverage.out && cat *.cover.out | grep -v mode: | sort -r | \
awk '{if($1 != last) {print $0;last=$1}}' >> coverage.out
rm -rf *.cover.out
