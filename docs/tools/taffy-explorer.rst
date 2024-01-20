taffy-explorer - UI for exploring and comparing pcap files
==========================================================

`taffy-explorer` acts a lot like a combination of `taffy-compare` and
`taffy-graph` combined in an interactive UI.  It has a detailed graph
at the top, a total traffic graph, a number of changeable UI fields
equivalent to the common command line arguments (eg, *-c*, *-x*, *-p*,
etc), and a table of generated differences based on these parameters.

**Note:** this is very much a work in progress and is usable today,
 but only barely.

Command Line Arguments
^^^^^^^^^^^^^^^^^^^^^^

.. sphinx_argparse_cli::
   :module: traffic_taffy.tools.explore
   :func: parse_args
   :hook:
   :prog: taffy-explorer
