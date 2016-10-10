# OnionScan - The Dark Web Forensics Toolkit

*Author: Sarah Jamie Lewis*
*Created: 2016-10-06*
*Status: Draft*
*Target: 0.2*

# Overview

   This document describes the goals, scope and direction of the OnionScan tool.
   
   
# Goals

   OnionScan is a free and open source tool for investigating the Dark Web. The
   audience for OnionScan is large and varied, for the purposes of this document
   we will divide the types of users into the following categories:

   * People with an intermediate level of knowledge who should be able to use OnionScan
     to find operational security issues with their site.
   * Researchers and Investigators who should be able to use OnionScan to 
     monitor and track Dark Web sites.

   These two distinct groups need different but related functionality and we should
   aim to serve both groups.
   
   Regardless of the expansion of the OnionScan tool it should always been possible
   for a naive user point OnionScan at a site and get immediate, useful results.
   
# In Scope

   OnionScan is primarily interested in automating the following functions:

   * Identifying misconfigurations in hidden services that may lead to deanonymization.
   * Identifying operational security violations that may lead to deanonymization.
   * Identifying correlations between multiple hidden services.
   * Providing a platform for further analysis of hidden services e.g classification.
   * Provide a way to store and track changes to services over time.
   
   In addition to the above, OnionScan should also act as a generic and 
   configurable crawler:
   
   * Discovering and following links to new services
   * Intelligently crawling sites for certain content e.g. users and listings 
     on marketplaces
   * Providing snapshots of pages now and in the past.
 
# Not In Scope

   OnionScan is not a general vulnerability scanner or security tool. We should
   not introduce features and scans that can be commonly found in other tools
   targetted at regular websites e.g. XSS detection.

