taffy-config - dump configuration structure to the console
----------------------------------------------------------

`taffy-config` shows the existing configuration structure that is
available to pass to the `traffic-taffy` tools using the `--config`
command line argument.

example usage
^^^^^^^^^^^^^

::

   $ taffy-config > defaults.yml

This will produce a defaults.yml file that can be edited.  Here's a
full dump as of version 0.9.2:

.. code-block:: yaml

    algorithms:
      correlation:
        correlation_method: spearman
        max_pivot: 1000
        minimum_correlation: 0.8
      correlationchanges:
        comparison_width: 15
        correlation_method: spearman
        minimum_change: 0.5
        slide_length: null
    compare:
      algorithm: statistical
      fsdb: false
      only_negative: false
      only_positive: false
      print_threshold: 0.0
      reverse_sort: false
      sort_by: delta%
      top_records: null
    config: null
    dissect:
      bin_size: null
      cache_file_suffix: taffy
      cache_pcap_results: false
      dissection_level: 2
      engines:
        scapy:
          temp_file_directory: null
          use_temp_files: false
      filter: null
      force_load: false
      force_overwrite: false
      ignore_list:
      - Ethernet_IP_TCP_seq
      - Ethernet_IP_TCP_ack
      - Ethernet_IPv6_TCP_seq
      - Ethernet_IPv6_TCP_ack
      - Ethernet_IPv6_TCP_Raw_load
      - Ethernet_IP_UDP_Raw_load
      - Ethernet_IP_UDP_DNS_id
      - Ethernet_IP_ICMP_IP in ICMP_UDP in ICMP_chksum
      - Ethernet_IP_ICMP_IP in ICMP_UDP in ICMP_Raw_load
      - Ethernet_IP_ICMP_IP in ICMP_chksum
      - Ethernet_IP_ICMP_IP in ICMP_id
      - Ethernet_IP_TCP_DNS_id
      - Ethernet_IPv6_UDP_DNS_id
      - Ethernet_IPv6_TCP_DNS_id
      - Ethernet_IP_id
      - Ethernet_IP_chksum
      - Ethernet_IP_UDP_chksum
      - Ethernet_IP_TCP_chksum
      - Ethernet_IP_TCP_window
      - Ethernet_IP_TCP_Raw_load
      - Ethernet_IP_UDP_Raw_load
      - Ethernet_IPv6_UDP_chksum
      - Ethernet_IPv6_fl
      - Ethernet_IP_ICMP_chksum
      - Ethernet_IP_ICMP_id
      - Ethernet_IP_ICMP_seq
      - Ethernet_IP_TCP_Padding_load
      - Ethernet_IP_TCP_window
      - Ethernet_IPv6_TCP_chksum
      - Ethernet_IPv6_plen
      - Ethernet_IP_TCP_Encrypted Content_load
      - Ethernet_IP_TCP_TLS_TLS_Raw_load
      layers: []
      maximum_cores: 20
      merge: false
      packet_count: 0
      use_modules: null
    graph:
      by_percentage: false
      interactive: false
      output_file: null
    limit_output:
      match_expression: null
      match_string: null
      match_value: null
      minimum_count: null
    log_level: info
    modules:
      ip2asn:
        database: ip2asn-combined.tsv
      psl:
        database: __internal__

Command Line Arguments
^^^^^^^^^^^^^^^^^^^^^^

.. sphinx_argparse_cli::
   :module: traffic_taffy.tools.config
   :func: taffy_config_parse_args
   :hook:
   :prog: taffy-config
