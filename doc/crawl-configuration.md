Crawl configuration
====================

Providing crawl configuration
------------------------------

The directory from which crawl configurations are fetched from is specified
using the command-line option `-crawlconfigdir <path>`.

In this directory there should be a file per hidden service that needs specific
configuration options. For example `ab23cd45ef67gh76.onion.json`; though the name of the file
is not parsed so any naming convention can be used.

Configuring the scan for a service does not automatically cause it to be
scanned. They still need to be specified explicitly, either on the command
line or in a `-list` file.

Configuration structure
------------------------

    {
	"onion": "aabbccddeeffgghh.onion",
	"base": "/forums",
	"exclude": [
	    "/profile",
	    "/settings"
	]
    }

The following configuration parameters can currently be specified:

- `onion`: The hostname of the service to configure scanning for. This should
  be just the hostname, and have no `http://` prefix or path components.

- `base`: configures the base path, relative to the root of the site (to ignore
  all other parts of a site and focus on a specific set of URLs e.g. `/forums`)

- `exclude`: tells the scanner to ignore URLs which contain one or more of the
  given strings - this allows explicitly ignoring uninteresting URLs (e.g.
  `/profile` or `/settings`) and also for avoiding URLs which might mess up the
  scan (e.g. `/logout`)
