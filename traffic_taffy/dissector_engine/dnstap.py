"""A dissection engine for quickly parsing and counting packets."""

from __future__ import annotations

from logging import error, debug
from traffic_taffy.dissector_engine.dpkt import DissectionEngineDpkt
from traffic_taffy.dissection import Dissection, PCAPDissectorLevel

import dnstap_pb
import fstrm


class DissectionEngineDNStap(DissectionEngineDpkt):
    """A dissection engine for parsing saved dnscap files."""

    # should be larger than any potentially stored DNS message
    READ_SIZE = 8192

    def __init__(self, *args: list, **kwargs: dict):
        """Create a dissection engine for parsing dnscap files."""
        super().__init__(*args, **kwargs)

    def load_data(self) -> Dissection:
        """loads the dnstap file into memory."""

        # technically a dnstap file, not a pcap_file
        with open(self.pcap_file, "rb") as fh:
            data = fh.read(self.READ_SIZE)

            # create the framing stream decoded
            stream = fstrm.FstrmCodec()
            success = stream.append_and_process(data)
            if not success:
                error("failed to read {self.pcap_file} as a fstrm")
                raise ValueError("failed to read input file")

            # the base header is just extra data about the file's producer
            # header =
            header = stream.decode()
            debug(f"header: {header[1]}")
            # read more data (see comment below)
            stream.append(fh.read(self.READ_SIZE - len(stream.buf)))

            # Create the dnstap protobuf parser
            dd = dnstap_pb.Dnstap()

            dissection = self.dissection
            level = self.dissector_level
            count = 0

            # loop through the stream and process each subsequent frame
            while stream.process():
                # pull the next frame out
                body = stream.decode()

                # parse it as a dnstap protobuf object
                dd.ParseFromString(body[2])
                message = dd.message

                self.start_packet(message.query_time_sec)

                # keep the buffer at the required size.
                stream.append(fh.read(self.READ_SIZE - len(stream.buf)))

                # determine if it's IPv4 or IPv6
                if message.socket_family == 1:
                    IP = "IP"
                    self.incr("Ethernet_type", 2048)
                    self.incr("Ethernet_IP_version", 4)
                elif message.socket_family == 2:
                    IP = "IPv6"
                    self.incr("Ethernet_type", 34525)
                    self.incr("Ethernet_IP_version", 6)
                else:
                    raise ValueError("unknown IP protocol in dnstap")
                prefix = "Ethernet_" + IP + "_"

                # set the source/dest addresses
                self.incr(prefix + "src", message.query_address)
                self.incr(prefix + "dst", message.response_address)

                # Determine the transport protocol
                # TODO(hardaker): read these names from the protobuf spec directly
                if message.socket_protocol == 1:
                    protocol_prefix = prefix + "UDP_"
                elif message.socket_protocol == 2:
                    protocol_prefix = prefix + "TCP_"
                elif message.socket_protocol == 3:
                    protocol_prefix = prefix + "DOT_"
                elif message.socket_protocol == 4:
                    protocol_prefix = prefix + "DOH_"
                elif message.socket_protocol == 5:
                    protocol_prefix = prefix + "DNSCryptUDP_"
                elif message.socket_protocol == 6:
                    protocol_prefix = prefix + "DNSCryptTCP_"
                elif message.socket_protocol == 7:
                    protocol_prefix = prefix + "DOQ_"
                else:
                    raise ValueError("unknown DNS socket protocol in dnstap")
                # TODO(hardaker): get full protocol list here

                self.incr(protocol_prefix + "sport", message.query_port)
                self.incr(protocol_prefix + "dport", message.response_port)

                if message.type & 0x01 == 1:  # query
                    self.incr(
                        protocol_prefix + "DNS_qr", 0
                    )  # query = 0 in the protocol
                else:
                    self.incr(
                        protocol_prefix + "DNS_qr", 1
                    )  # response = 1 in the protocol

                count += 1
                if self.maximum_count and count >= self.maximum_count:
                    break

                if level >= PCAPDissectorLevel.COMMON_LAYERS.value:
                    self.dissect_dns(message.query_message, protocol_prefix + "DNS_")

        return dissection
