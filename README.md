# <img src="onionscan.png" alt="OnionScan"/>

[![Build Status](https://travis-ci.org/s-rah/onionscan.svg?branch=onionscan-0.2)](https://travis-ci.org/s-rah/onionscan)

## What is OnionScan?

OnionScan is a free and open source tool for investigating the Dark Web.

The purpose of this tool is to make you a better onion service provider. You owe
it to yourself and your users to ensure that attackers cannot easily exploit and 
deanonymize.

OnionScan is not a general vulnerability scanner or security tool. It does not
feature scans that can be commonly found in other tools targetted at regular
websites e.g. XSS detection.

## Go Dependencies

* golang.org/x/net/proxy - For the Tor SOCKS Proxy connection.
* github.com/rwcarlsen/goexif - For EXIF data extraction.
* github.com/mvdan/xurls - For some URL parsing.
* github.com/HouzuoGuo/tiedot/db - For crawl database.

## Installing

### Grab with go get

`go get github.com/s-rah/onionscan`

### Compile/Run from git cloned source

`go install github.com/s-rah/onionscan` and then run the program in `./bin/onionscan`.

Or, you can just do `go run github.com/s-rah/onionscan.go` to execute without compiling.

## Running

For a simple report detailing the high, medium and low risk areas found:

`./bin/onionscan blahblahblah.onion`

The most interesting output comes from the verbose option:

`./bin/onionscan --verbose blahblahblah.onion`

There is also a JSON output, if you want to integrate with something else:

`./bin/onionscan --jsonReport blahblahblah.onion`

If you would like to use a proxy server listening on something other that `127.0.0.1:9050`, then you can use the --torProxyAddress flag:

`./bin/onionscan --torProxyAddress=127.0.0.1:9150 blahblahblah.onion`

To only scan for the web service and skip the other scans

`./bin/onionscan --scans web --torProxyAddress=127.0.0.1:9150 blahblahblah.onion`

More detailed documentation on usage can be found in [doc](doc/README.md).

## What is scanned for?

An list of privacy and security problems which are detected by OnionScan can be
found [here](doc/what-is-scanned-for.md).
