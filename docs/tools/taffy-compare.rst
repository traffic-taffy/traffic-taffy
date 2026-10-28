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

Sometimes *delta#* is negative, but *delta%* is positive.  Why?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A common case when analyzing data with `taffy-compare` is that the
*delta#* may be positive, and the *delta%* may be negative.

The thing to remember is that the *delta%* shows the percentage of the
total number of values seen **for that variable**.  If there are less
actual numbers of that variable in the second capture, then the
percentage of a value can be higher or lower and that is independent
of the total count of that value, which is what *delta#* shows.

As an example, if you have two recordings of Internet traffic and the
first has 900 IPv4 UDP packets to port 53 in it and 100 UDP packets to
port 123, and the second has 400 IPv4 UDP packets to port 53, 100
packets to IPv4 UDP port 123 and 500 IPv6 UDP packets to port 53, then
the total number of packets for IPv4 UDP packets to port 53 *will go
down*, but the fraction of IPv4 UDP packets to port 53 vs port 123
will actually go up (because 900/1000 is higher than 400/500).

In tabular form:

======= ============= ===== =====
Capture What          Value Count
======= ============= ===== =====
left    IPv4 UDP port 53    600
left    IPv4 UDP port 123   400
right   IPv4 UDP port 53    400
right   IPv4 UDP port 123   100
======= ============= ===== ====

So if we use these numbers to calculate the results seen from the
comparison output we find (note: just ipv4 udp shown):

============= ===== ===== ====== ====== ===== ====== ======
What          Value left# right# Delta# left% right% Delta%
============= ===== ===== ====== ====== ===== ====== ======
IPv4 UDP port    53   600   400    -200   60    80     20
IPv4 UDP port   123   400   100    -300   40    20     -20
============= ===== ===== ====== ====== ===== ====== ======

The important take aways:

- the total count went down in UDP traffic between the left and the right
- there was a shift in the percentage of that traffic toward port 53
- thus, the *delta#* was always lower, but the *delta%* for port 53 went up

You might want to read this description twice, and read the math below:

The Raw Math
^^^^^^^^^^^^

- left# port 53  = 600
- right# port 53 = 400
- delta# port 53 = 400 - 600 = -200

- left% port 53  = 600 / (600 + 400) = 60%
- right% port 53 = 400 / (400 + 100) = 80%
- delta% port 53 = 80% - 60% = 20%

Command Line Arguments
^^^^^^^^^^^^^^^^^^^^^^

..
   .. sphinx_argparse_cli::
      :module: traffic_taffy.tools.compare
      :func: compare_parse_args
      :hook:
      :prog: taffy-compare
