# OnionScan Database Proposal

*Author: Sarah Jamie Lewis*
*Created: 2016-10-06*
*Status: Draft*
*Target: 0.2*

## Overview

   This document describes the requirements and design for the 
   internal OnionScan database.
   
### Raw Crawl Data

   * Web Page Snapshots
   * Image Snapshots
   * Raw Protocol Info e.g. SSH Key, Fingerprint and Software Banner
   * Crawl Metadata e.g. Date/Time and Length
   
   Keyed against the fully qualified URL of the determined protocol e.g.
   `http://example.onion/index.php` or `ssh://example.com:29`
   
   All of these URLs are tied to the scan report.

### Identifier Nodes

   * Identifiers derived form raw crawl data e.g. Bitcoin Addresses, 
     IP Addresses etc.
     
   Stored as a triple: `onion hostname`, `type of identifier`, `identifier string` 
   e.g. `example.onion`, `bitcoin_address`, `1CFCJHzSAC12VaJt2s1BwXgpb6beo9yWZU`

   The user should be able to search any of the derived identifiers.
 
### Correlation Search
   
   * Finding services that share the same SSH key fingerprint.
   * Finding services that list the same Bitcoin Address.
     
    Using the Identifier Nodes, indexed by `identifier string`, we can efficiently
    search for onions that share the same identifiers.
     
### General Search

   * Ad-hoc search requires in response to user data e.g. "find all the sites
     that contain the word 'drug'"
     
   This is the trickiest one to implement. At the moment the only way to do this
   would be to perform a full-scan search across the whole raw crawl data. In the
   future we may want to optimize this - but as it stands, this inefficiency seems
   like a good trade off with the rest of the database design.
     
   

   
   
