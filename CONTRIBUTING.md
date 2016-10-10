# General Guidelines for Contributing

* **Important:** Make sure you are developing off of the `onionscan-0.2` branch - it has many new features that make adding new code much easier.
* Issues are the best place for design discussions and questions. 
* Documentation and Tests are always welcome.
* When submitting a PR tests are automatically run with Travis-CI please ensure that your code does not break this integration.


# What should I work on?

Check out the [Hacktoberfest](https://github.com/s-rah/onionscan/issues?q=is%3Aissue+is%3Aopen+label%3AHacktoberfest) label for projects that will likely be the easiest for newcomers. [Help Wanted](https://github.com/s-rah/onionscan/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) is also good to check for larger tasks.

Issues marked [idea/ needs design](https://github.com/s-rah/onionscan/issues?q=is%3Aissue+is%3Aopen+label%3A%22idea+%2F+needs+design%22) should begin with a document linked from the issue to allow input as these are likely to have the biggest impact on OnionScan's overall architecture.

If in doubt, you can always contact @s-rah

# What if I have a new idea?

Awesome. You can generally either add an issue if it is still in the thought stages or a PR if you have code. If you are unsure about whether a new idea is suitable for OnionScan please open an issue. Generally the following are always encouraged:

* New identifier correlations (past examples: email addresses, cryptocurrency id's)
* New analytics techniques (past examples: ssh key correlations, image fingerprinting)
* New protocols (that are likely being used by onion services, past examples: bitcoin, irc, ssh)
* New Miconfigurations/Exploits (past examples: mod_status)
* Bug fixes
* Usability Improvements
* Tests and Documentation 

If in doubt, you can always contact @s-rah
