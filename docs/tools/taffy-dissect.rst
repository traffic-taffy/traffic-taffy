taffy-dissect - dissect and count packet types within a pcap file
-----------------------------------------------------------------

`taffy-dissect` takes dissects all or part of a *pcap* file and counts
each of the packet components seen.  It provides a quick way to
discover the most common packet components that make up a larger body
of traffic.

Command Line Arguments
^^^^^^^^^^^^^^^^^^^^^^

.. sphinx_argparse_cli::
   :module: traffic_taffy.tools.compare
   :func: parse_args
   :hook:
   :prog: taffy-dissect
