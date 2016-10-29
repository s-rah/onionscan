# OnionScan Correlation Lab

<img src="./images/correlation-lab-main.png" title="The main OnionScan Correlation Lab Screen"/>

# Discovery Identity Correlations

The OnionScan Correlation Lab is a rather unique environment. The Lab provides
you with a way of uncovering relationships between different onion sites.

The best way to often start is to enter the name of an onion service you are
interested in, in the search bar:

<img src="./images/correlation-search.png" title="Searching for an OnionSite"/>

If you have scanned the site with OnionScan then the search should result in a
page displaying all kinds of correlations that OnionScan has detected:

<img src="./images/correlation-summary.png" title="Correlation Lab Summary"/>

You can look around this page and find identifiers and other information that
may indicate potential deanonymization vectors.

OnionScan also attempts to highlight the most important information at the top
of the page - for example, in the screen above OnionScan has added the page title
along with two tags indicating that OnionScan found a mod_status leak on the 
service in question.

<img src="./images/correlation-title.png" title="Correlation Lab Summary"/>

# Tagging Correlations

To help with investigations, The Correlation Lab supports the tagging of search
results - you can tag any given search results, including the results for other
tags, in the left-hand column. 

<img src="./images/correlation-tagging.png" title="Correlation Lab Options Menu, showing the Tagging feature."/>

You can then search for all tagged pages using the search feature - or by clicking
on the tag:

<img src="./images/correlation-custom-tag.png" title="Correlation Lab Tagging Summary, showing two sites with the same tag"/>



