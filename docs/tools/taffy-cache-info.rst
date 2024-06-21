taffy-cache-info - display details of a taffy cache file
-----------------------------------------------------------------

`taffy-cache-info` shows the details of a traffic-taffy cache file.
When any of the tools are passed a *-C* flag, a cache file is written
to speed future loading of pcap files.  Normally this cache file is
saved with a *.taffy* extension.

example usage
-------------

::

   taffy-cache-info dns-traffic.pcap
   ===== dns-traffic.pcap ======
   PCAP_DISSECTION_VERSION 7
   file                 dns-traffic.pcap
   parameters:
       pcap_file        dns-traffic.pcap
       bin_size         1
       dissector_level  10
       pcap_filter      None
       maximum_count    0
       ignore_list      ['Ethernet.IP.TCP.chksum', 'Ethernet.IP.TCP.Padding.load', 'Ethernet.IP.TCP.seq', 'Ethernet.IP.ICMP.seq',
   'Ethernet.IPv6.TCP.seq', 'Ethernet.IP.ICMP.chksum', 'Ethernet.IPv6.TCP.chksum', 'Ethernet.IP.TCP.DNS.id', 'Ethernet.IP.ICMP.id',
   'Ethernet.IPv6.UDP.chksumEthernet.IPv6.fl', 'Ethernet.IPv6.TCP.ack', 'Ethernet.IPv6.UDP.DNS.id', 'Ethernet.IP.chksum', 'Ethernet.IP.id',
   'Ethernet.IP.TCP.ack', 'Ethernet.IP.UDP.DNS.id', 'Ethernet.IP.UDP.chksum', 'Ethernet.IPv6.plen', 'Ethernet.IPv6.TCP.DNS.id']
   data info:
       timestamps:      83
       first:           1567838478
       last:            1567838559


Command Line Arguments
^^^^^^^^^^^^^^^^^^^^^^

.. sphinx_argparse_cli::
   :module: traffic_taffy.tools.cache_info
   :func: parse_args
   :hook:
   :prog: taffy-cache-info
