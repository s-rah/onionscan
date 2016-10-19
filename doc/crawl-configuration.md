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
                ],
                "relationships":[
                        {
                          "name":"User", 
                          "triggeridentifierregex":"index\\.php\\?action=profile;u=([0-9]*)",
                          "extrarelationships":[
                                {
                                  "name":"Name",
                                  "regex":"<div class=\"username\"><h4>(.*) <span class=\"position\">"
                                },
                                {
                                  "name":"Position",
                                  "regex":"<span class=\"position\">(.*)</span></h4>"
                                }
                          ]
                       },
                       {
                         "name":"Post", 
                         "triggeridentifierregex":"index\\.php\\?topic=([0-9]*)",
                         "extrarelationships":[
                               {
                                  "name":"Topic",
                                  "regex":"Topic: (.*) &nbsp;\\(Read"
                                }
                          ]
                        }
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
  
- `relationships`: configures OnionScan with custom relationships. Like many
  preconfigured relationships, these are specified by a trigger URL regular expression.
  The `triggeridentifierregex` *must* specify 1 group that contains the Identifer of the
  relationships. This will be stored in OnionScan as a relationship mapping `Onion`->`Identifier`
  and given the `from` attribute of the relationship name. 
  
  For example, in the above structure, two relationships are defined `User` and
  `Post`.
  
  For `User` the trigger regex is `index\.php\?action=profile;u=([0-9]*)` which 
  when found will store an identifier marking the users profile ID as the identifier.
  
  `User` also specifies two sub-relationships `Name` and `Position` which are
  specified by different regular expressions that should be found on the same page
  as the one identified by the trigger URL. These will be stored by OnionScan
  as `Onion`->`Name` and `Onion`->`Postion` with the `from` attribute set to the
  originally captured `ID`.
  
