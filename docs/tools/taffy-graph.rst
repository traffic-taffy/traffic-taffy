taffy-graph - graph packet components in pcap files
===================================================

`taffy-graph` takes one or multiple *PCAP* files and graphs portions
of packets seen within each file.  You will need to pass the portionsn
of the packet you wish to graph (using *-m*), and optionally limiting
which values of those fields are selected for graphing (using *-M* and
*-c*).

Note that the *-c* field selects the minimum count needed per value
seen in *one* time-bin.

To graph all of the traffic regardless of packet types, use *-m
__TOTAL___* along with *-M packet*.


example usage
-------------

::

   taffy-graph -c 100 -m qname -d 10 -o dns-qnames.png dns-traffic.pcap

Command Line Arguments
^^^^^^^^^^^^^^^^^^^^^^

.. sphinx_argparse_cli::
   :module: traffic_taffy.tools.graph
   :func: parse_args
   :hook:
   :prog: taffy-graph
