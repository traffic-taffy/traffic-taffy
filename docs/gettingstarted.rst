Getting Started
===============

Installation
------------

Using *pip* or *pipx*:

::

    pip install traffic-taffy

**Note:** python by default installs programs to $HOME/.local/bin --
make sure this is in your PATH.


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

Input File Types Supported
--------------------------

The *traffic-taffy* tools currently support reading these types of
files:

* PCAP files
* DNSTAP files (0.6 and later)
* xz, gzip or bzip2 compressed PCAP files

Important Command Line Options
------------------------------

All of the tools contain a number of important options that are
important to understand.  Most importantly, **it is highly recommended
you always use cache files (add the -C switch)**.

* -C, --cache-pcap-results:

  Turns on caching of analyzed pcaps to a cache file that typically
  ends in *".taffy"*.  The use of this field *always* is highly
  recommended.  If a cache file exists, the tools will all load it
  instead of re-parsing the associated pcap file.

* -d LEVEL, --dissection-level LEVEL:

  Selects a dissection level to use.  The current dissection levels
  supported are ranked from fastest to slowest (deepest packet
  inspection):

  * 1: A fast parser that just counts traffic levels.  Not likely super
    useful as very little is extracted, but it is the fastest.

  * 2: Extracts packet information down the protocol/port-numbers such
    as UDP and port 53, for example, but does not dive further into
    the associated packets.

  * 3: Looks for packets of high interest and parses them:

    - DNS
    - more TBD

  * 10: The deepest packet parser which extracts all information
    possible from the packets (uses the `scapy` dissection engine).
    This is definitely the best choice, but it is very slow in
    comparison to other parsing levels.  Note that `traffic-taffy`
    does try to make use of all available CPU cores during processing.

  *Warning: watch out for over-use of memory -- no memory limitation
  techniques currently exist*

Speed comparison for different levels
-------------------------------------

The following table shows the differences in speeds for different
levels on a sample PCAP file containing 10,000 captured DNS packets.
Note: This is not an accurate study at all, just an example.

=========== ============================
Level       Speed
=========== ============================
1           0.196s
2           0.521s
3           0.861s
10          4.299s
=========== ============================


Typical workflow
----------------

1. Gather traffic in two pcap files.  One file should be a period of
   traffic which is considered "normal".  Gather another file where
   the traffic is either entirely within a "spike" or at least is
   "mostly the spike".

2. Run `taffy-compare` on the two files starting with some high level
   limiting arguments, such as:

   * turn on caching: *-C*
   * limit to just packet field values with at least a count of 10000:
     *-c 10000*
   * only show the top 10 differences found: *-x 10*
   * only show differences with at least a 5% usage change in counts:
     *-t 5*
   * set a starting detail level of 2, which is a fast pcap parser
     that only looks at high level packet data (down to UDP/TCP port
     numbers but not lower level packet details): *-d 2*

3. Iteratively re-run `taffy-compare` lower each of the above fields
   until you begin to see a picture of what the traffic spikes consist
   of.

4. Use `taffy-graph` to graph the resulting fields (use the *-m*
   switch for name matching a field), passing it similar arguments to
   what was used to produce a good report in steps 2-3.

5. Alternatively, you can try the `taffy-explorer` UI for performing
   all of these tasks at the start as the tool keeps all information
   in memory and allows you to iterate and discover at a faster rate.
   Start with the same command line options listed in #2 above, and
   use the UI configuration to change the values at run-time.

See :doc:`the case study <casestudy>` for a complete example.
