# <img src="onionscan.png" alt="OnionScan"/>

The purpose of this tool is to make you a better onion service provider. You owe
it to yourself and your users to ensure that attackers cannot easily exploit and 
deanonymize.

## Go Dependencies

* h12.me/socks - For the Tor SOCKS Proxy connection.
* github.com/xiam/exif - For EXIF data extraction.
* github.com/mvdan/xurls - For some URL parsing.

## OS Package Dependencies

* libexif-dev on Debian based OS
* libexif-devel on Fedora

## Installing

### Install OS dependencies

* On Debian based operating systems: `sudo apt-get install libexif-dev`
* On Fedora based operating systems: `sudo dnf install libexif-devel`

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

## Apache mod_status Protection

This [should not be news](http://arstechnica.com/security/2016/02/default-settings-in-apache-may-decloak-tor-hidden-services/), you should not have it enabled. If you do have it enabled, attacks can:

* Build a better fingerprint of your server, including php and other software versions.
* Determine client IP addresses if you are co-hosting a clearnet site.
* Determine your IP address if your setup allows.
* Determine other sites you are co-hosting.
* Determine how active your site is.
* Find secret or hidden areas of your site
* and much, much more.

Seriously, don't even run the tool, go to your site and check if you have `/server-status`
reachable. If you do, turn it off!

## Open Directories 

Basic web security 101, if you leave directories open then people are going to scan
them, and find interesting things - old versions of images, temp files etc.

Many sites use common structures `style/`, `images/` etc. The tool checks for
common variations, and allows the user to submit others for testing. 

## EXIF Tags

Whether you create them yourself or allow users to upload images, you need to
ensure the metadata associated with the image is stripped.

Many, many websites still do not properly sanitise image data, leaving themselves
or their users at risk of deanonymization.

## Server Fingerprint

Sometimes, even without mod_status we can determine if two sites are hosted on
 the same infrastructure. We can use the following attributes to make this distinction:

* Server HTTP Header
* Technology Stack (e.g. php, jquery version etc.)
* Website folder layout e.g. do you use `/style` or `/css` or do you use wordpress.
* Fingerprints of images
* GPG Versions being used.

