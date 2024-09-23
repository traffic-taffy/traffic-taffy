"""A dissection engine for quickly parsing and counting packets."""

from __future__ import annotations

from logging import debug, error
from traffic_taffy.dissector_engine import DissectionEngine
from traffic_taffy.dissection import Dissection, PCAPDissectorLevel
from pcap_parallel import PCAPParallel

import dpkt
import socket


class DissectionEngineDpkt(DissectionEngine):
    """A dissection engine for quickly parsing and counting packets."""

    DNS_PORT: int = 53
    HTTP_PORT: int = 80
    IPV6_VERSION: int = 6

    def __init__(self, *args: list, **kwargs: dict):
        """Create a dissection engine for quickly parsing and counting packets."""
        super().__init__(*args, **kwargs)
        self.data_link_type = None

    def load_data(self) -> None:
        """Load the specified PCAP into memory."""
        # Note: called from self.load() after initializing
        if isinstance(self.pcap_file, str):
            pcap = dpkt.pcap.Reader(PCAPParallel.open_maybe_compressed(self.pcap_file))
        else:
            # it's an open handle already
            pcap = dpkt.pcap.Reader(self.pcap_file)

        self.data_link_type = pcap.datalink()

        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)
        pcap.dispatch(self.maximum_count, self.callback)

    def dissect_dns(self, dns_data: bytes, prefix: str = None) -> None:
        try:
            dns = dpkt.dns.DNS(dns_data)
        except dpkt.dpkt.UnpackError:
            self.incr(prefix + "unparsable_dns", "PARSE_ERROR")
            debug("DPKT unparsable DNS data")
            return
        except UnicodeDecodeError:
            self.incr(prefix + "unparsable_utf8", "PARSE_ERROR")
            debug("DPKT unparsable UTF8 data")
            return

        self.incr(prefix + "id", dns.id)
        self.incr(prefix + "opcode", dns.op)
        # self.incr(prefix + "qd", dns.qd)
        # self.incr(prefix + "an", dns.an)
        # self.incr(prefix + "ns", dns.ns)
        # self.incr(prefix + "ar", dns.ar)

        # flags and headers
        self.incr(prefix + "rcode", dns.rcode)
        self.incr(prefix + "ra", dns.ra)
        self.incr(prefix + "rd", dns.rd)
        self.incr(prefix + "tc", dns.tc)
        self.incr(prefix + "z", dns.zero)
        self.incr(prefix + "opcode", dns.opcode)
        self.incr(prefix + "qr", dns.qr)
        self.incr(prefix + "aa", dns.aa)
        # self.incr(prefix + "ad", dns.ad)

        # record counts
        self.incr(prefix + "qdcount", len(dns.qd))
        self.incr(prefix + "ancount", len(dns.an))
        self.incr(prefix + "nscount", len(dns.ns))
        self.incr(prefix + "arcount", len(dns.ar))

        for record in dns.qd:
            self.incr(prefix + "qd_qname", record.name + ".")
            self.incr(prefix + "qd_qtype", record.type)
            self.incr(prefix + "qd_qclass", record.cls)

        for record in dns.an:
            self.incr(prefix + "an_rrname", record.name + ".")
            self.incr(prefix + "an_type", record.type)
            self.incr(prefix + "an_rclass", record.cls)
            self.incr(prefix + "an_rdlen", record.rlen)
            self.incr(prefix + "an_ttl", record.ttl)

            # concepts from dpkt.dns.DNS_upnack_rdata()
            if record.type == dpkt.dns.DNS_A:
                # TODO(hardaker): decode this hex streem to an IP
                self.incr(prefix + "an_rdata", record.ip)
            elif record.type == dpkt.dns.DNS_AAAA:
                # TODO(hardaker): decode this hex streem to an IP(v6)
                self.incr(prefix + "an_rdata", record.ip6)
            elif record.type == dpkt.dns.DNS_NS:
                self.incr(prefix + "an_nsname", record.nsname)
            elif record.type == dpkt.dns.DNS_CNAME:
                self.incr(prefix + "an_cname", record.cname)
            elif record.type == dpkt.dns.DNS_CNAME:
                self.incr(prefix + "an_ptrname", record.ptrname)
            elif record.type == dpkt.dns.DNS_MX:
                self.incr(
                    prefix + "an_preference",
                    record.preference,
                )
                self.incr(prefix + "an_mxname", record.mxname)
            elif record.type == dpkt.dns.DNS_SRV:
                self.incr(prefix + "an_priority", record.priority)
                self.incr(prefix + "an_weight", record.weight)
                self.incr(prefix + "an_port", record.port)
                self.incr(prefix + "an_srvname", record.srvname)
            elif record.type in (dpkt.dns.DNS_TXT, dpkt.dns.DNS_HINFO):
                for text_record in record:
                    self.incr(prefix + "an_text", text_record)
            elif record.type == dpkt.dns.DNS_SOA:
                self.incr(prefix + "an_mname", record.mname + ".")
                self.incr(prefix + "an_rname", record.rname)
                self.incr(prefix + "an_serial", record.serial)
                self.incr(prefix + "an_refresh", record.refresh)
                self.incr(prefix + "an_refresh", record.refresh)
                self.incr(prefix + "an_retry", record.retry)
                self.incr(prefix + "an_expire", record.expire)
                self.incr(prefix + "an_minimum", record.minimum)

        for record in dns.ns:
            self.incr(prefix + "ns_rrname", record.name + ".")
            self.incr(prefix + "ns_type", record.type)
            self.incr(prefix + "ns_rclass", record.cls)
            # self.incr(prefix + "ns_rdata", record.nsname)
            self.incr(prefix + "ns_ttl", record.ttl)

        for record in dns.ar:
            self.incr(prefix + "ar_rrname", record.name + "_")
            self.incr(prefix + "ar_type", record.type)
            self.incr(prefix + "ar_rclass", record.cls)
            self.incr(prefix + "ar_ttl", record.ttl)
            self.incr(prefix + "ar_rdlen", record.rlen)

    def callback(self, timestamp: float, packet: bytes) -> None:
        """Dissect and count one packet."""
        # if binning is requested, save it in a binned time slot
        dissection: Dissection = self.dissection

        self.start_packet(int(timestamp), dissection)

        level = self.dissector_level
        if isinstance(level, PCAPDissectorLevel):
            level = level.value

        if level >= PCAPDissectorLevel.THROUGH_IP.value:
            if self.data_link_type == 1:
                # Ethernet based encapsulation
                eth = dpkt.ethernet.Ethernet(packet)
                # these names are designed to match scapy names
                self.incr("Ethernet_dst", eth.dst)
                self.incr("Ethernet_src", eth.src)
                self.incr("Ethernet_type", eth.type)
                data = eth.data
            elif self.data_link_type == 101:
                # Raw IP encapsulation
                if packet[0] == 0x45:
                    data = dpkt.ip.IP(packet)
                elif packet[0] == 0x60:
                    data = dpkt.ip6.IP6(packet)
                else:
                    error("Unknown IP version in data")
                    raise ValueError("unknown IP version")
            else:
                error(f"unknown link type: {self.data_link_type}")
                raise ValueError("unknown link type")

            # TODO(hardaker): add ip6.IP6 support
            next_layer = None
            udp = None
            tcp = None

            if isinstance(data, dpkt.ip.IP):
                ip = data
                udp = None
                tcp = None

                ipver = "IP"
                if ip.v == DissectionEngineDpkt.IPV6_VERSION:
                    ipver = "IPv6"

                prefix = f"Ethernet_{ipver}_"

                # TODO(hardaker): make sure all these match scapy
                self.incr(prefix + "dst", ip.dst)
                self.incr(prefix + "src", ip.src)
                self.incr(prefix + "df", ip.df)
                self.incr(prefix + "offset", ip.offset)
                self.incr(prefix + "tos", ip.tos)
                self.incr(prefix + "len", ip.len)
                self.incr(prefix + "id", ip.id)
                self.incr(prefix + "hl", ip.hl)
                self.incr(prefix + "rf", ip.rf)
                self.incr(prefix + "p", ip.p)
                self.incr(prefix + "chksum", ip.sum)
                self.incr(prefix + "tos", ip.tos)
                self.incr(prefix + "version", ip.v)
                self.incr(prefix + "ttl", ip.ttl)

                next_layer = ip.data

            elif isinstance(data, dpkt.ip6.IP6):
                ip6 = data

                ipver = "IPv6"
                prefix = f"Ethernet_{ipver}_"

                # TODO(hardaker): make sure all these match scapy
                socket.inet_ntop(
                    socket.AF_INET6,
                    b"\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                )

                self.incr(prefix + "dst", socket.inet_ntop(socket.AF_INET6, ip6.dst))
                self.incr(prefix + "src", socket.inet_ntop(socket.AF_INET6, ip6.src))
                self.incr(prefix + "fl", ip6.flow)
                self.incr(prefix + "hlim", ip6.hlim)
                self.incr(prefix + "nh", ip6.nxt)
                self.incr(prefix + "plen", ip6.plen)
                self.incr(prefix + "tc", ip6.fc)
                next_layer = ip6.data

            if next_layer:
                if isinstance(next_layer, dpkt.udp.UDP):
                    udp = next_layer
                    self.incr(prefix + "UDP_sport", udp.sport)
                    self.incr(prefix + "UDP_dport", udp.dport)
                    self.incr(prefix + "UDP_len", udp.ulen)
                    self.incr(prefix + "UDP_chksum", udp.sum)

                    # TODO(hardaker): handle DNS and others for level 3

                elif isinstance(next_layer, dpkt.tcp.TCP):
                    tcp = next_layer
                    self.incr(prefix + "TCP_sport", tcp.sport)
                    self.incr(prefix + "TCP_dport", tcp.dport)
                    self.incr(prefix + "TCP_seq", tcp.seq)
                    self.incr(prefix + "TCP_flags", tcp.flags)
                    # self.incr(prefix + "TCP_reserved", tcp.reserved)
                    self.incr(prefix + "TCP_window", tcp.win)
                    self.incr(prefix + "TCP_chksum", tcp.sum)
                    self.incr(prefix + "TCP_options", tcp.opts)

                if level >= PCAPDissectorLevel.COMMON_LAYERS.value:
                    http = None
                    if udp and DissectionEngineDpkt.DNS_PORT in (udp.sport, udp.dport):
                        self.dissect_dns(udp.data, prefix + "UDP_DNS_")
                        return

                    if tcp and DissectionEngineDpkt.DNS_PORT in (tcp.sport, tcp.dport):
                        self.dissect_dns(tcp.data, prefix + "TCP_DNS_")
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
                                self.incr(prefix + "Method", method)
                            else:
                                prefix += "Response_"

                        except dpkt.dpkt.UnpackError:
                            self.incr(
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
                                self.incr(prefix + header, value.capitalize())
