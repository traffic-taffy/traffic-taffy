Extra Processing Modules
========================

A number of additional processing modules exist to add supplemental
information to the dissected *PCAP* or *DNSTAP* files.  These can be
added to processing using the `-x` command line option to all the
tools.

ip2asn
------

The `ip2asn` adds additional information based on the IP addresses
seen in the traffic.  Specifically, with `-x ip2asn` information about
each address's *ASN*, *country* and *owner* will be added to the
output.

Note that this requires downloading the ip2asn-combined.tsv file and
decompressing it from https://ip2asn.com/ .

psl
---

The `psl` module adds Public Suffix List information extracted from
the DNS names found within the dissected traffic.  Specifically, with
`-x psl` information about the domain name's *prefix* (e.g. "www"),
registered *domain* (e.g. "example.com") and the *public suffix*
(e.g. "com" or "co.uk").

labels
------

The `labels` module takes DNS names found in the packet and breaks
them into pieces.  Specifically, a packet field name ending in
`_qname` (for example) will create multiple other sub-records called
`_qname_tld`, `_qname_sld`, `_qname_3ld`, `_qname_4ld`, and
`_qname_5ld`.
