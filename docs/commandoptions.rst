Command Line Options
====================

The `traffic-taffy` tools support various command line options that
dictate how the tools both parse pcap datasets, and how they report
the results.

Options affecting packet parsing and dissection
-----------------------------------------------

======================= ===============
Option                  Description
======================= ===============
  -d DISSECTION_LEVEL   Dump to various levels of detail (1-10, with 10
                        is the most detailed and slowest) (default: 2)
  -I [IGNORE_LIST ...]  A list of (unlikely to be useful) packet
                        fields to ignore.  Ignoring some sections will
                        speed up parsing some and prevent displaying
                        more useless fields like TCP sequence numbers,
                        eg.  See the --help output for a default list.
  -n PACKET_COUNT       Maximum number of packets to analyze (default: 0)
  -b BIN_SIZE           Time-bin the results into this many seconds (default: 1)
  -F FILTER             tcpdump/libpcap filter to apply to the pcap
                        file when processing (default: None)
  -L [LAYERS ...]       List of extra layers to load (eg: tls, http, etc).
                        Some parsing engines (including level 10)
                        won't load some layers without requesting
                        them.  A list of these is TBD still.
  -C                    Cache and use PCAP results into/from a cache file file
  --cs                  The suffix file to use when creating cache files (default: taffy)
  --force-overwrite     Force continuing with an incompatible cache (and rewriting it)
  --force-load          Force continuing with an incompatible cache (trying to load it anyway)
======================= ===============

Options limiting the display output
-----------------------------------

These apply to `taffy-compare`, `taffy-dissect` and `taffy-graph`
generally


======================= ===============
Option                  Description
======================= ===============
  -m MATCH_STRING       Only report on data with this substring in the header
  -M [MATCH_VALUE ...]  Only report on data with particular substrings in the packet value
  -c MINIMUM_COUNT      Don't include results without this high of a record count
  -t PRINT_THRESHOLD    Don't print results with abs(percent) less than this threshold
  -P                    Only show positive changing entries
  -N                    Only show negative changing entries
  -r                    Reverse the sort order of reports
======================= ===============

taffy-compare output options
----------------------------

======================= ===============
Option                  Description
======================= ===============
-F                      Output FSDB formatted data (tab-separated with a header)
-s SORT_BY              Sort and limit output based on this column name (default: "delta %")
  -x TOP_RECORDS        Show the top N records from each section
======================= ===============

taffy-graph output options
--------------------------

======================= ===============
Option                  Description
======================= ===============
-o OUTPUT_PNG           Where to store the resulting graph
-p                      Graph field percentages rather than actual values
-i                      Interactive repeated graphing -- don't use this yet
======================= ===============


Debugging options
-----------------

Generally most people won't need these, but if you want to increase or
decrease debugging output:

======================= ===============
Option                  Description
======================= ===============
--ll LOG_LEVEL          Change the minimum logging output level (debug, info, warning, error)
--dont-fork             Don't let `taffy-dissect` use parallel processing
======================= ===============
