"""A dissection engine for quickly parsing and counting packets."""

from __future__ import annotations

from logging import debug
from traffic_taffy.dissector_engine import DissectionEngine
from traffic_taffy.dissection import Dissection, PCAPDissectorLevel
from pcap_parallel import PCAPParallel

import dpkt


class DissectionEngineDpkt(DissectionEngine):
    """A dissection engine for quickly parsing and counting packets."""

    DNS_PORT: int = 53
    HTTP_PORT: int = 80
    IPV6_VERSION: int = 6

    def __init__(self, *args: list, **kwargs: dict):
        """Create a dissection engine for quickly parsing and counting packets."""
        super().__init__(*args, **kwargs)

    def load_data(self) -> None:
        """Load the specified PCAP into memory."""
        # Note: called from self.load() after initializing
        if isinstance(self.pcap_file, str):
            pcap = dpkt.pcap.Reader(PCAPParallel.open_maybe_compressed(self.pcap_file))
        else:
            # it's an open handle already
            pcap = dpkt.pcap.Reader(self.pcap_file)
        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)
        pcap.dispatch(self.maximum_count, self.callback)

    def incr(self, dissection: Dissection, name: str, value: str | int) -> None:
        """Increment a given name and value counter."""
        if name not in self.ignore_list:
            dissection.incr(name, value)

    def dissect_dns(self, dns_data: bytes, prefix: str = None) -> None:
        try:
            dns = dpkt.dns.DNS(dns_data)
        except dpkt.dpkt.UnpackError:
            self.incr(self.dissection, prefix + "UDP_DNS_unparsable", "PARSE_ERROR")
            debug("DPKT unparsable DNS data")
            return

        dissection = self.dissection

        self.incr(dissection, prefix + "id", dns.id)
        self.incr(dissection, prefix + "opcode", dns.op)
        # self.incr(dissection, prefix + "qd", dns.qd)
        # self.incr(dissection, prefix + "an", dns.an)
        # self.incr(dissection, prefix + "ns", dns.ns)
        # self.incr(dissection, prefix + "ar", dns.ar)

        # flags and headers
        self.incr(dissection, prefix + "rcode", dns.rcode)
        self.incr(dissection, prefix + "ra", dns.ra)
        self.incr(dissection, prefix + "rd", dns.rd)
        self.incr(dissection, prefix + "tc", dns.tc)
        self.incr(dissection, prefix + "z", dns.zero)
        self.incr(dissection, prefix + "opcode", dns.opcode)
        self.incr(dissection, prefix + "qr", dns.qr)
        self.incr(dissection, prefix + "aa", dns.aa)
        # self.incr(dissection, prefix + "ad", dns.ad)

        # record counts
        self.incr(dissection, prefix + "qdcount", len(dns.qd))
        self.incr(dissection, prefix + "ancount", len(dns.an))
        self.incr(dissection, prefix + "nscount", len(dns.ns))
        self.incr(dissection, prefix + "arcount", len(dns.ar))

        for record in dns.qd:
            self.incr(dissection, prefix + "qd_qname", record.name + ".")
            self.incr(dissection, prefix + "qd_qtype", record.type)
            self.incr(dissection, prefix + "qd_qclass", record.cls)

        for record in dns.an:
            self.incr(dissection, prefix + "an_rrname", record.name + ".")
            self.incr(dissection, prefix + "an_type", record.type)
            self.incr(dissection, prefix + "an_rclass", record.cls)
            self.incr(dissection, prefix + "an_rdlen", record.rlen)
            self.incr(dissection, prefix + "an_ttl", record.ttl)

            # concepts from dpkt.dns.DNS_upnack_rdata()
            if record.type == dpkt.dns.DNS_A:
                # TODO(hardaker): decode this hex streem to an IP
                self.incr(dissection, prefix + "an_rdata", record.ip)
            elif record.type == dpkt.dns.DNS_AAAA:
                # TODO(hardaker): decode this hex streem to an IP(v6)
                self.incr(dissection, prefix + "an_rdata", record.ip6)
            elif record.type == dpkt.dns.DNS_NS:
                self.incr(dissection, prefix + "an_nsname", record.nsname)
            elif record.type == dpkt.dns.DNS_CNAME:
                self.incr(dissection, prefix + "an_cname", record.cname)
            elif record.type == dpkt.dns.DNS_CNAME:
                self.incr(dissection, prefix + "an_ptrname", record.ptrname)
            elif record.type == dpkt.dns.DNS_MX:
                self.incr(
                    dissection,
                    prefix + "an_preference",
                    record.preference,
                )
                self.incr(dissection, prefix + "an_mxname", record.mxname)
            elif record.type == dpkt.dns.DNS_SRV:
                self.incr(dissection, prefix + "an_priority", record.priority)
                self.incr(dissection, prefix + "an_weight", record.weight)
                self.incr(dissection, prefix + "an_port", record.port)
                self.incr(dissection, prefix + "an_srvname", record.srvname)
                self.incr(dissection, prefix + "an_off", record.off)
            elif record.type in (dpkt.dns.DNS_TXT, dpkt.dns.DNS_HINFO):
                for text_record in record:
                    self.incr(dissection, prefix + "an_text", text_record)
            elif record.type == dpkt.dns.DNS_SOA:
                self.incr(dissection, prefix + "an_mname", record.mname + ".")
                self.incr(dissection, prefix + "an_rname", record.rname)
                self.incr(dissection, prefix + "an_serial", record.serial)
                self.incr(dissection, prefix + "an_refresh", record.refresh)
                self.incr(dissection, prefix + "an_refresh", record.refresh)
                self.incr(dissection, prefix + "an_retry", record.retry)
                self.incr(dissection, prefix + "an_expire", record.expire)
                self.incr(dissection, prefix + "an_minimum", record.minimum)

        for record in dns.ns:
            self.incr(dissection, prefix + "ns_rrname", record.name + ".")
            self.incr(dissection, prefix + "ns_type", record.type)
            self.incr(dissection, prefix + "ns_rclass", record.cls)
            # self.incr(dissection, prefix + "ns_rdata", record.nsname)
            self.incr(dissection, prefix + "ns_ttl", record.ttl)

        for record in dns.ar:
            self.incr(dissection, prefix + "ar_rrname", record.name + "_")
            self.incr(dissection, prefix + "ar_type", record.type)
            self.incr(dissection, prefix + "ar_rclass", record.cls)
            self.incr(dissection, prefix + "ar_ttl", record.ttl)
            self.incr(dissection, prefix + "ar_rdlen", record.rlen)

    def callback(self, timestamp: float, packet: bytes) -> None:
        """Dissect and count one packet."""
        # if binning is requested, save it in a binned time slot
        dissection: Dissection = self.dissection

        self.start_packet(int(timestamp), dissection)
        dissection.incr(Dissection.TOTAL_COUNT, dissection.TOTAL_SUBKEY)

        level = self.dissector_level
        if isinstance(level, PCAPDissectorLevel):
            level = level.value

        if level >= PCAPDissectorLevel.THROUGH_IP.value:
            eth = dpkt.ethernet.Ethernet(packet)
            # these names are designed to match scapy names
            self.incr(dissection, "Ethernet_dst", eth.dst)
            self.incr(dissection, "Ethernet_src", eth.src)
            self.incr(dissection, "Ethernet_type", eth.type)

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                udp = None
                tcp = None

                ipver = "IP"
                if ip.v == DissectionEngineDpkt.IPV6_VERSION:
                    ipver = "IPv6"

                prefix = f"Ethernet_{ipver}_"

                # TODO(hardaker): make sure all these match scapy
                self.incr(dissection, prefix + "dst", ip.dst)
                self.incr(dissection, prefix + "src", ip.src)
                self.incr(dissection, prefix + "df", ip.df)
                self.incr(dissection, prefix + "offset", ip.offset)
                self.incr(dissection, prefix + "tos", ip.tos)
                self.incr(dissection, prefix + "len", ip.len)
                self.incr(dissection, prefix + "id", ip.id)
                self.incr(dissection, prefix + "hl", ip.hl)
                self.incr(dissection, prefix + "rf", ip.rf)
                self.incr(dissection, prefix + "p", ip.p)
                self.incr(dissection, prefix + "chksum", ip.sum)
                self.incr(dissection, prefix + "tos", ip.tos)
                self.incr(dissection, prefix + "version", ip.v)
                self.incr(dissection, prefix + "ttl", ip.ttl)

                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    self.incr(dissection, prefix + "UDP_sport", udp.sport)
                    self.incr(dissection, prefix + "UDP_dport", udp.dport)
                    self.incr(dissection, prefix + "UDP_len", udp.ulen)
                    self.incr(dissection, prefix + "UDP_chksum", udp.sum)

                    # TODO(hardaker): handle DNS and others for level 3

                elif isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    self.incr(dissection, prefix + "TCP_sport", tcp.sport)
                    self.incr(dissection, prefix + "TCP_dport", tcp.dport)
                    self.incr(dissection, prefix + "TCP_seq", tcp.seq)
                    self.incr(dissection, prefix + "TCP_flags", tcp.flags)
                    # self.incr(dissection, prefix + "TCP_reserved", tcp.reserved)
                    self.incr(dissection, prefix + "TCP_window", tcp.win)
                    self.incr(dissection, prefix + "TCP_chksum", tcp.sum)
                    self.incr(dissection, prefix + "TCP_options", tcp.opts)

                if level >= PCAPDissectorLevel.COMMON_LAYERS.value:
                    http = None
                    if udp and DissectionEngineDpkt.DNS_PORT in (udp.sport, udp.dport):
                        self.dissect_dns(udp.data, prefix + "UDP_DNS_")
                        return

                    if tcp and DissectionEngineDpkt.DNS_PORT in (tcp.sport, tcp.dport):
                        self.dissect_dns(udp.data, prefix + "UDP_DNS_")
                        return

                    if (
                        tcp
                        and DissectionEngineDpkt.HTTP_PORT in (tcp.sport, tcp.dport)
                        and len(tcp.data) > 0
                    ):
                        try:
                            (command, _, content) = tcp.data.partition(b"\r\n")
                            http = dpkt.http.Message(content)
                            prefix += "TCP_HTTP 1_"

                            (method, _, remaining) = command.partition(b" ")
                            method = method.decode("utf-8")
                            if method in [
                                "GET",
                                "POST",
                                "HEAD",
                                "PUT",
                                "DELETE",
                                "CONNECT",
                                "TRACE",
                                "PATCH",
                                "OPTIONS",
                            ]:
                                prefix += "Request_"
                                self.incr(dissection, prefix + "Method", method)
                            else:
                                prefix += "Response_"

                        except dpkt.dpkt.UnpackError:
                            self.incr(
                                dissection,
                                prefix + "TCP_HTTP_unparsable",
                                "PARSE_ERROR",
                            )
                            debug("DPKT unparsable HTTP data")
                            return

                    if http:
                        for header in http.headers:
                            parts = http.headers[header]
                            if not isinstance(parts, list):
                                parts = [parts]
                            for value in parts:
                                self.incr(
                                    dissection, prefix + header, value.capitalize()
                                )
