taffy-compare - compare reference and anomaly traffic
-----------------------------------------------------

.. _taffycompare:

`taffy-compare` takes one or multiple *PCAP* files and examines the
contents for differences.

If one PCAP file is provided, it will compare each time bin (default 1
second) against each next time bin.

If two PCAP files are provided, it will compare the contents of the
first ("Left") against the next ("Right").

Output
^^^^^^

The output of the tool produces a report showing the differences
between the *Left* and *Right* samples, in 6 different columns.  Each
output section includes a title line prefixed by equal signs
("=======") showing what Left and Right are mapping to (files or time
ranges).  Then each reported protocol field is reported as a header
prefixed with dashes ("-----") and the protocol field name (such as
"*Ethernet.IP.UDP.dport*").  The columns reported for each protocol
field are as follows:

======== ==============================================================================
Column   Description
======== ==============================================================================
Value    The *value* for the protocol field being being reported
Left     The *absolute count* of the value in the *Left* sample
Right    The *absolute count* of the value seen in the *Right* sample
Delta    The absolute count deltas -- *Right - Left*
Left %   The *percentage of this value* vs all the values from the left protocol field
Right %  The *percentage of this value* vs all the values from the right protocol field
Delta %  The different between the *Left* and *Right* percentage columns
======== ==============================================================================

The default sort order is by *Delta %*, but can be changed with the
`-s` command line switch.

Command Line Arguments
^^^^^^^^^^^^^^^^^^^^^^

..
   .. sphinx_argparse_cli::
      :module: traffic_taffy.tools.compare
      :func: compare_parse_args
      :hook:
      :prog: taffy-compare
