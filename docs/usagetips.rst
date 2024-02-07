Usage Tips
==========

Some general tips for use the traffic-taffy tools:

Use caching
-----------

Use the `-C` switch to write cache files next to the processed PCAP
files when possible.  This takes a bit of disk space but greatly feeds
up future runs.

Start with fast comparisons of limited packet numbers
-----------------------------------------------------

Especially when you need rapid answers for responding to incoming
attacks, start with a fixed number of packets (e.g. 10,000) and use a
faster dissection level (3).

======== =============================
Argument Description
======== =============================
-d 3     set the dissection level to 3
-n 10000 parse at most 10k packets
======== =============================

(Eventually you’ll always want level 10, but it’s more CPU and memory
intensive)

Start comparisons with large filtering thresholds
-------------------------------------------------

For filtering the output to show only the major differences, limit
what is reported to a high number of minimum enumerations, and/or only
with at least a decent percentage change.  Also, limit each section
results to just the top 10 or so differences.  You might want to sort
by a particular column (e.g. right) too if sorting by the delta
percentage isn't showing interesting data.

**Note:** these clauses are logically ANDed together.

======== =============================
Argument Description
======== =============================
-c 1000  Show only differences with at least 1000 counts
-t 10    Show only differences with at least a 10% change:
-x 10    Show only the top 10 differences:
-s right Optionally sort by the right column instead of the delta %
======== =============================
