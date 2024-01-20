Getting Started
===============

Installation
------------

Using *pip* or *pipx*:

::

    pip install traffic-taffy


Example usage
-------------

Suppose you have two pcap files (*file1.pcap* and *file2.pcap*), one
captured during "normal times" and another when some anomaly has
caused a spike.  The following example command line uses the
*taffy-compare* utility to show the top 10 differences (*-x 10*) per
packet section in the new traffic with at least 1000 records (*-c
100*) in the packet section.  For speed of analysis, we use a maximum
of 10000 records per pcap file (*-n 10000*)

::

   taffy-compare -n 10000 -x 10 -c 100 file1.pcap file2.pcap
