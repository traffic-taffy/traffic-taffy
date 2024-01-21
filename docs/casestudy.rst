An Example Case Study
=====================

The best way of showing how `traffic-taffy` can be used to analyze
large datasets, we will walk through an example dataset to analyze its
contents.

The Dataset
-----------

The dataset under study will be the [B_Root_Anomaly-20190907]_ dataset
that contains traffic from a DDoS attack on the b.root-servers.net DNS
root server, published by the [ANTLab]_ (of which the author is
associated with).  Note that this dataset contains a very large spike
of traffic that is not particularly difficult for a human to
necessarily perform this analysis by hand.  Thus, it serves as a good
example so that the data can be analyzed in multiple fashions in order
to come up with hopefully similar conclusions.  .

The README file's description of this event is as follows:


Parameter   Value
=========== ============================
Duration    06:45:19 UTC to 06:46:53 UTC
Sources     Spoofed (Randomized)
Query name  No fixed query name
Packet size 554 bytes requests

Using this informationn we select the following files from the dataset
to study from the LAX anycast instance and that directly surround the
event in question.  Thus, we will use just these files, which we'll
just call **FILES** when using all of them in the rest of this
document.

.. [B_Root_Anomaly-20190907] https://comunda.isi.edu/artifact/view/1437

.. [ANTLab] https://ant.isi.edu/

* 20190907-064359-01587810.lax.pcap.xz
* 20190907-064519-01587811.lax.pcap.xz
* 20190907-064545-01587812.lax.pcap.xz
* 20190907-064550-01587813.lax.pcap.xz
* 20190907-064557-01587814.lax.pcap.xz
* 20190907-064603-01587815.lax.pcap.xz
* 20190907-064610-01587816.lax.pcap.xz
* 20190907-064653-01587817.lax.pcap.xz

Producing Cache Files
---------------------

Using a *level 10 dissection* analyzer, with *1 second bin time* we
can produce a graph of the total traffic to get a feel for the size of
the event.  use *-C* to enable caching of the results (note: this
first run will take a while to complete).  We use the special
identifier *__TOTAL__*  to select just the total number of packets to
create this graph.

::

   taffy-graph -C -b 1 -m __TOTAL__ -o total-traffic.png *.pcap.xz

Which produces the following graph:

.. image:: images/total-traffic.png
   :width: 600px
