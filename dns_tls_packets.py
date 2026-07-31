#!/usr/bin/env python3

from collections import namedtuple

from protocol_tools import *

_dnssec_enabled = False


class ClientRequest:
    __slots__ = (
        '_data', '_dns_header', '_dns_query',

        'address', 'sendto', 'intf',
        'dns_id', 'top_domain',

        'qr', 'op', 'aa', 'tc', 'rd',
        'ra', 'zz', 'ad', 'cd', 'rc',

        'qname', 'qtype', 'qclass',
        'question_record', 'additional_records',
        'send_data'
    )

    def __init__(self, address, sock_info):
        self.address = address

        if (sock_info):
            self.sendto = sock_info.sendto

        self.top_domain = False if address[0] else True

        self.dns_id    = 1
        self.send_data = b''
        self.additional_records = b''

    # if called before the parse method has been called, the request will not be known yet. this is mostly redundant
    # to the console log message output while relaying a request so consider removing this.
    def __str__(self):
        try:
            return f'dns_query(host={self.address[0]}, port={self.address[1]}, request={self.qname})'
        except AttributeError:
            return f'dns_query(host={self.address[0]}, port={self.address[1]}, request=Unknown)'

    def parse(self, data):
        if (len(data) < 12):
            raise ValueError('dns packet too short')

        _dns_header, _dns_query = data[:12], data[12:]

        # ================
        # REQUEST HEADER
        # ================
        dns_header = dns_header_unpack(_dns_header)
        self.dns_id = dns_header[0]

        self.qr = dns_header[1] >> 15 & 1
        self.op = dns_header[1] >> 11 & 15
        self.aa = dns_header[1] >> 10 & 1
        self.tc = dns_header[1] >> 9  & 1
        self.rd = dns_header[1] >> 8  & 1
        self.ra = dns_header[1] >> 7  & 1
        self.zz = dns_header[1] >> 6  & 1
        self.ad = dns_header[1] >> 5  & 1
        self.cd = dns_header[1] >> 4  & 1
        self.rc = dns_header[1]       & 15

        # ================
        # QUESTION RECORD
        # ================
        # www.micro.com or micro.com || sd.micro.com
        offset, local_domain, self.qname = parse_query_name(_dns_query, data, qname=True)

        if (len(_dns_query) < offset + 4):
            raise ValueError('truncated question section')

        self.qtype, self.qclass = double_short_unpack(_dns_query[offset:])
        self.question_record = _dns_query[:offset+4]
        self.additional_records = _dns_query[offset+4:]

        return local_domain

    def generate_cached_response(self, cached_domain):
        if (self.send_data):
            raise RuntimeError('send data has already been created for this query.')

        send_data = bytearray()

        send_data += build_dns_response_hdr(self.dns_id, len(cached_domain.records), rd=self.rd, cd=self.cd)
        send_data += self.question_record

        ttl_bytes = long_pack(cached_domain.ttl)
        for record in cached_domain.records:
            send_data += record.name
            send_data += record.qtype
            send_data += record.qclass
            send_data += ttl_bytes
            send_data += record.data

        self.send_data = send_data

    def generate_negative_response(self):
        '''build a synthetic NXDOMAIN response for a negatively cached domain.'''
        if (self.send_data):
            return

        send_data = bytearray()
        send_data += build_dns_response_hdr(self.dns_id, 0, rd=self.rd, cd=self.cd, rc=3)
        send_data += self.question_record
        self.send_data = send_data

    def generate_dns_query(self, dns_id: int) -> None:
        if (self.send_data):
            raise RuntimeError('send data has already been created for this query.')

        # initializing byte array with (2) bytes. these get overwritten with query len actual after processing
        send_data = bytearray(2)

        header_and_question = build_dns_query_hdr(dns_id, 1, cd=(0 if _dnssec_enabled else self.cd)) + domain_stob(self.qname) + double_short_pack(self.qtype, 1)

        # privacy hardening for this upstream/WAN facing leg: strip any EDNS Client Subnet option (this relay
        # must never forward the LAN client's address to the public resolver) and pad the query to a fixed
        # block size (RFC 8467) so its raw length leaks less about which domain is being resolved. this always
        # results in exactly one additional record (an OPT record), so the additional record count is hardcoded
        # to 1 above rather than being conditional on whether the client happened to send one itself.
        send_data += header_and_question
        send_data += sanitize_and_pad_edns(self.additional_records, len(header_and_question), dnssec=_dnssec_enabled)

        send_data[:2] = short_pack(len(send_data) - 2)

        self.send_data = send_data

    @classmethod
    def generate_local_query(cls, qname: str, keepalive: bool = False) -> None:
        '''alternate constructor for creating locally generated queries (top domains).'''

        self = cls(NULL_ADDR, None)

        # hardcoded qtype can change if needed.
        self.qname = qname
        self.qtype = 1
        self.cd    = 0 if _dnssec_enabled else 1

        if (keepalive):
            self.generate_dns_query(DNS.KEEPALIVE)

        return self


# ================
# SERVER RESPONSE
# ================
_records_container = namedtuple('record_container', 'counts records')
_resource_records = namedtuple('resource_records', 'resource authority')

class _ResourceRecord:
    __slots__ = ('name', 'qtype', 'qclass', 'ttl', 'data')

    def __init__(self, name, qtype, qclass, ttl, data):
        self.name = name
        self.qtype = qtype
        self.qclass = qclass
        self.ttl = ttl
        self.data = data

    def __bytes__(self):
        return self.name + self.qtype + self.qclass + self.ttl + self.data

_RESOURCE_RECORD = _ResourceRecord

_MINIMUM_TTL = long_pack(MINIMUM_TTL)
_DEFAULT_TTL = long_pack(DEFAULT_TTL)

def ttl_rewrite(data, dns_id, len=len, min=min, max=max):
    dns_header, dns_payload = data[:12], data[12:]

    # converting external/unique dns id back to original dns id of client
    send_data = bytearray(short_pack(dns_id))

    # ================
    # HEADER
    # ================
    _dns_header = dns_header_unpack(dns_header)

    resource_count = _dns_header[3]
    authority_count = _dns_header[4]
    # additional_count = _dns_header[5]
    rcode = _dns_header[1] & 15

    send_data += dns_header[2:]

    # ================
    # QUESTION RECORD
    # ================
    # www.micro.com or micro.com || sd.micro.com
    offset, _ = parse_query_name(dns_payload, data)

    question_record = dns_payload[:offset + 4]

    send_data += question_record

    # ================
    # RESOURCE RECORD
    # ================
    resource_records = dns_payload[offset + 4:]

    # offset is reset to prevent carry over from above.
    offset, original_ttl, clamped_ttl, record_cache = 0, 0, 0, []

    # parsing standard and authority records
    for record_count in [resource_count, authority_count]:

        # cap the loop at the maximum number of records that could possibly fit in the
        # remaining payload (each record is at least ~12 bytes) so a forged/tampered
        # record count from the upstream cannot cause excessive CPU or memory churn.
        remaining = len(resource_records) - offset
        max_records = min(record_count, max(remaining // 12, 0))
        for _ in range(max_records):
            record_type, record, offset = _parse_record(resource_records, offset, dns_payload)

            # TTL rewrite done on A records which functionally clamps TTLs between a min and max value. CNAME is listed
            # first, followed by A records so the original_ttl var will be whatever the last A record ttl parsed is.
            # generally all A records have the same ttl. CNAME ttl can differ, but will get clamped with A so will
            # likely end up the same as A records.
            if (record_type in (DNS.A, DNS.CNAME, DNS.AAAA)):
                if (len(record.ttl) != 4):
                    raise ValueError('truncated ttl')
                original_ttl = long_unpack(record.ttl)[0]
                if (original_ttl >= 0x80000000):
                    original_ttl = 0
                clamped_ttl = max(MINIMUM_TTL, min(original_ttl, DEFAULT_TTL))
                record.ttl = long_pack(clamped_ttl)

                send_data += bytes(record)

                # limits A record caching so we aren't caching excessive amount of records with the same qname
                if (len(record_cache) < MAX_A_RECORD_COUNT or record_type != DNS.A):
                    record_cache.append(record)

            # dns system level, mail, and txt records don't need to be clamped and will be relayed to client as is
            else:
                send_data += bytes(record)

    # keeping any additional records intact
    # TODO: see if modifying/ manipulating additional records would be beneficial or even useful in any way
    send_data += resource_records[offset:]

    if (record_cache):
        return send_data, CACHED_RECORD(int(fast_time()) + clamped_ttl, clamped_ttl, record_cache), rcode

    return send_data, None, rcode

def _parse_record(resource_records, total_offset, dns_query):
    current_record = resource_records[total_offset:]

    offset, _ = parse_query_name(current_record, dns_query)

    # resource record data len. generally 4 for ip address, but can vary. calculating first so we can single shot
    # create byte container below.
    if (len(current_record) < offset + 10):
        raise ValueError('truncated resource record')

    dt_len = btoia(current_record[offset + 8:offset + 10])

    resource_record = _RESOURCE_RECORD(
        current_record[:offset],
        current_record[offset:offset + 2],
        current_record[offset + 2:offset + 4],
        current_record[offset + 4:offset + 8],
        current_record[offset + 8:offset + 10 + dt_len]
    )

    # name len + 2 bytes(length field) + 8 bytes(type, class, ttl) + data len
    total_offset += offset + 10 + dt_len

    return btoia(resource_record.qtype), resource_record, total_offset
