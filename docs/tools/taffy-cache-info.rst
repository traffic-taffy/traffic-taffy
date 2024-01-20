taffy-dissect - dissect and count packet types within a pcap file
-----------------------------------------------------------------

`taffy-cache-info` shows the details of a traffic-taffy cache file.
When any of the tools are passed a *-C* flag, a cache file is written
to speed future loading of pcap files.  Normally this cache file is
saved with a *.taffy* extension.

Command Line Arguments
^^^^^^^^^^^^^^^^^^^^^^

.. sphinx_argparse_cli::
   :module: traffic_taffy.tools.cache_info
   :func: parse_args
   :hook:
   :prog: taffy-cache-info
