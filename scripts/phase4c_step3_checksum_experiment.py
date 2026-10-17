#!/usr/bin/env python3
# SOC-003 Phase 4C Step 3 -- Step 6 alert analysis helper.
#
# Purpose: determine the exact reason the managed ruleset's packet-anomaly rules
# (sid 2200073/2200074/2200075, "SURICATA IPv4/TCPv4/UDPv4 invalid checksum")
# fired during the offline replay of the Phase 3D benign guest capture.
#
# Method (offline, no live capture, no config change):
#   1. Parse the classic-pcap copy of the Phase 3D capture.
#   2. Recompute the IPv4 header checksum of every packet (RFC 1071) and
#      compare it with the on-wire value.
#   3. For the flagged packets, recompute the TCP/UDP transport checksum
#      (with pseudo-header) as well.
#   4. Write two derived evidence subsets:
#        subset-orig.pcap : first N flagged packets, unmodified
#        subset-ipfix.pcap: the same packets with the IPv4 checksum corrected
#      Replaying both through Suricata with only the three anomaly rules
#      isolates whether the TCPv4/UDPv4 alerts are an independent transport
#      problem or a consequence of the invalid IPv4 header checksum.
#
# Read-only on the source capture; all outputs are new files.

import struct
import sys
import os

SRC_PCAP = os.path.join(os.path.dirname(__file__),
                        "../evidence/phase4c-ruleset/analysis/checksum-experiment/nc3d-classic.pcap")
OUT_DIR = os.path.join(os.path.dirname(__file__),
                       "../evidence/phase4c-ruleset/analysis/checksum-experiment")
N_KEEP = 12  # packets kept per derived subset


def ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip_checksum(ip_header: bytes) -> int:
    return ones_complement_sum(ip_header)


def tcp_udp_checksum(ip_header: bytes, segment: bytes, proto: int) -> int:
    """Checksum of a TCP/UDP segment with the IPv4 pseudo-header."""
    src = ip_header[12:16]
    dst = ip_header[16:20]
    pseudo = src + dst + bytes([0, proto]) + struct.pack(">H", len(segment))
    return ones_complement_sum(pseudo + segment)


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise SystemExit("not a classic pcap file (magic %r)" % magic)
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != 1:
        raise SystemExit("expected LINKTYPE_ETHERNET, got %d" % linktype)
    pkts = []
    off = 24
    idx = 0
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        frame = data[off + 16:off + 16 + incl]
        pkts.append((idx, ts_sec, ts_usec, frame))
        off += 16 + incl
        idx += 1
    return pkts


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for idx, ts_sec, ts_usec, frame in packets:
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
            f.write(frame)


def sum_with_csum_field(data: bytes) -> int:
    """RFC 1071 sum INCLUDING the existing checksum field.

    For a correctly checksummed header/segment this sum equals 0xFFFF.
    """
    return ones_complement_sum_raw(data)


def ones_complement_sum_raw(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def parse_l3(frame):
    """Return (ip_header_bytes, l4_offset, proto) or None for non-IPv4."""
    if len(frame) < 14:
        return None
    etype = struct.unpack(">H", frame[12:14])[0]
    if etype != 0x0800:
        return None
    ip = frame[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    proto = ip[9]
    return ip[:ihl], ihl, proto


def main():
    pkts = read_pcap(SRC_PCAP)
    print(f"packets parsed: {len(pkts)}")

    stats = {
        "non_ipv4": 0,
        "ip_csum_good": 0,
        "ip_csum_bad": 0,
        "ip_bad_proto": {"tcp": 0, "udp": 0, "other": 0},
        "tcp_csum_among_ip_bad": {"good": 0, "bad": 0},
        "udp_csum_among_ip_bad": {"good": 0, "bad": 0},
    }
    flagged = []  # (packet_tuple, kind, fix_frame)

    for pkt in pkts:
        parsed = parse_l3(pkt[3])
        if parsed is None:
            stats["non_ipv4"] += 1
            continue
        ip_hdr, ihl, proto = parsed
        on_wire = struct.unpack(">H", ip_hdr[10:12])[0]
        # RFC 1071 verification: sum of the header including the checksum
        # field must be 0xFFFF for a valid checksum.
        full_sum = sum_with_csum_field(ip_hdr)
        zeroed = bytearray(ip_hdr)
        zeroed[10:12] = b"\x00\x00"
        computed = ones_complement_sum(bytes(zeroed))
        if full_sum != 0xFFFF and computed != on_wire:
            stats["ip_csum_bad"] += 1
            # transport-layer verification uses the frame's L4 bytes,
            # bounded by the IPv4 total-length field (ip_hdr holds only
            # the IPv4 header, so the L4 slice must come from the frame)
            ip_total = struct.unpack(">H", ip_hdr[2:4])[0]
            end = min(14 + ip_total, len(pkt[3]))
            l4 = pkt[3][14 + ihl:end]
            if proto == 6:
                stats["ip_bad_proto"]["tcp"] += 1
                if len(l4) >= 20:
                    seg = l4
                    full_sum = sum_with_csum_field(
                        struct.pack(">4s4sBBH", ip_hdr[12:16], ip_hdr[16:20], 0, 6,
                                    len(seg)) + seg)
                    wire = struct.unpack(">H", l4[16:18])[0]
                    kind = "good" if full_sum == 0xFFFF else "bad"
                    stats["tcp_csum_among_ip_bad"][kind] += 1
            elif proto == 17:
                stats["ip_bad_proto"]["udp"] += 1
                if len(l4) >= 8:
                    seg = l4
                    full_sum = sum_with_csum_field(
                        struct.pack(">4s4sBBH", ip_hdr[12:16], ip_hdr[16:20], 0, 17,
                                    len(seg)) + seg)
                    wire = struct.unpack(">H", l4[6:8])[0]
                    kind = "good" if full_sum == 0xFFFF else "bad"
                    stats["udp_csum_among_ip_bad"][kind] += 1
            else:
                stats["ip_bad_proto"]["other"] += 1
            # build fixed copy: recompute IPv4 header checksum only
            fixed_hdr = bytearray(ip_hdr)
            fixed_hdr[10:12] = b"\x00\x00"
            fix = ones_complement_sum(bytes(fixed_hdr))
            fixed_hdr[10:12] = struct.pack(">H", fix)
            frame = pkt[3][:14] + bytes(fixed_hdr) + pkt[3][14 + ihl:]
            flagged.append((pkt, "ip_bad", frame))
        else:
            stats["ip_csum_good"] += 1

    print("stats:", stats)

    subset = [f[0] for f in flagged[:N_KEEP]]
    fixed = []
    for pkt, _, fixframe in flagged[:N_KEEP]:
        fixed.append((pkt[0], pkt[1], pkt[2], fixframe))

    write_pcap(os.path.join(OUT_DIR, "subset-orig.pcap"), subset)
    write_pcap(os.path.join(OUT_DIR, "subset-ipfix.pcap"), fixed)
    print(f"wrote subsets: subset-orig.pcap ({len(subset)} pkts), subset-ipfix.pcap ({len(fixed)} pkts)")


if __name__ == "__main__":
    main()
