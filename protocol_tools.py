#!/usr/bin/env python3

from dns_tls_constants import *

def parse_query_name(data, dns_query=None, *, qname=False):
    '''parses dns name from sent in data. uses overall dns query to follow pointers. will return
    name and offset integer value if qname arg is True otherwise will only return offset.'''
    offset, contains_pointer, query_name = 0, False, []

    # TODO: this could be problematic since we slice down data. from what i my limited brain understands at the moment,
    #  data should never be an emtpy byte string if non malformed. the last iteration would have a null byte which is
    #  what this condition is actually testing against for when to stop iteration.
    #       // testing suggests this is fine for now
    while data[0]:

        # adding 1 to section_len to account for itself
        section_len, data = data[0], data[1:]

        # pointer value check. this used to be a separate function, but it felt like a waste so merged it.
        # NOTE: is this a problem is we don't pass in the reference query? is it possible for a pointer to be present in
        # cases where this function is used for non primary purposes?
        if (section_len & 192 == 192):

            # calculates the value of the pointer then uses value as original dns query index. this used to be a
            # separate function, but it felt like a waste so merged it. (-12 accounts for header not included)
            data = dns_query[((section_len << 8 | data[0]) & 16383) - 12:]

            contains_pointer = True

        else:
            # name len + integer value of initial length
            offset += section_len + 1 if not contains_pointer else 0

            query_name.append(data[:section_len].decode())

            # slicing out processed section
            data = data[section_len:]

    # increment offset +2 for pointer length or +1 for termination byte if name did not contain a pointer
    offset += 2 if contains_pointer else 1

    # evaluating qname for .local domain or non fqdn
    local_domain = True if len(query_name) == 1 or (query_name and query_name[-1] == 'local') else False

    if (qname):
        return offset, local_domain, '.'.join(query_name)

    return offset, local_domain

def domain_stob(domain_name):
    domain_bytes = byte_join([
        byte_pack(len(part)) + part.encode('utf-8') for part in domain_name.split('.')
    ])

    # root query (empty string) gets eval'd to length 0 and doesnt need a term byte. ternary will add term byte, if the
    # domain name is not a null value.
    return domain_bytes + b'\x00' if domain_name else domain_bytes

# will create dns header specific to response. default resource record count is 1
def build_dns_response_hdr(dns_id, record_count=1, *, rd=1, ad=0, cd=0, rc=0):
    qr, op, aa, tc, ra, zz = 1,0,0,0,1,0
    f = (qr << 15) | (op << 11) | (aa << 10) | (tc << 9) | (rd << 8) | \
        (ra <<  7) | (zz <<  6) | (ad <<  5) | (cd << 4) | (rc << 0)

    return dns_header_pack(dns_id, f, 1, record_count, 0, 0)

# will create dns header specific to request/query. default resource record count is 1, additional record count optional
def build_dns_query_hdr(dns_id, arc=0, *, cd):
    qr, op, aa, tc, rd, ra, zz, ad, rc = 0,0,0,0,1,0,0,0,0
    f = (qr << 15) | (op << 11) | (aa << 10) | (tc << 9) | (rd << 8) | \
        (ra <<  7) | (zz <<  6) | (ad <<  5) | (cd << 4) | (rc << 0)

    return dns_header_pack(dns_id, f, 1, 0, 0, arc)

def _parse_single_opt_record(additional_records):
    '''best effort parse of a raw additional records section, returning (udp_size, ext_rcode_flags, options) if
    it consists of EXACTLY one well formed EDNS0 OPT record (name=root, type=41) -- the overwhelmingly common
    real world shape when a dns client includes one at all. options is a list of [code, data] lists (mutable,
    since callers filter/append to it). returns None for anything else (no additional records, multiple/non-OPT
    records, or anything that doesn't parse cleanly) so the caller can fall back to leaving things completely
    untouched rather than risking corrupting an unusual/malformed packet.'''
    if (len(additional_records) < 11 or additional_records[0] != 0):
        return None

    rtype, udp_size = double_short_unpack(additional_records[1:5])
    if (rtype != DNS.OPT):
        return None

    ext_rcode_flags = additional_records[5:9]
    rdlength = short_unpack(additional_records[9:11])[0]
    rdata, trailer = additional_records[11:11 + rdlength], additional_records[11 + rdlength:]
    if (trailer or len(rdata) != rdlength):
        return None

    options, idx = [], 0
    while (idx + 4 <= len(rdata)):
        code, opt_len = double_short_unpack(rdata[idx:idx + 4])
        opt_data = rdata[idx + 4:idx + 4 + opt_len]
        if (len(opt_data) != opt_len):
            return None

        options.append([code, opt_data])
        idx += 4 + opt_len

    if (idx != len(rdata)):
        return None

    return udp_size, ext_rcode_flags, options

def sanitize_and_pad_edns(additional_records, unpadded_len):
    '''privacy hardening for the upstream (WAN facing) leg of the relay:

      1. strips any EDNS Client Subnet option (RFC 7871) -- this relay exists to keep the LAN client's
         address private from the public resolver, so that option must never be forwarded upstream regardless
         of whether the originating client (or an upstream forwarder feeding this relay) included one.
      2. adds an EDNS Padding option (RFC 7830), sized so the overall query lands on an EDNS_PADDING_BLOCK
         boundary (RFC 8467's recommendation specifically for DNS-over-TLS/HTTPS), so raw query length alone
         leaks less about which domain is being resolved to anything observing the encrypted TLS stream.

    unpadded_len is the length, in bytes, of the dns message (header + question) NOT including these additional
    records, needed to compute how much padding lands the total on a block boundary.

    if additional_records is non-empty and doesn't parse as exactly one well formed OPT record, it is returned
    completely unmodified rather than risking corrupting an unusual/malformed packet -- the client just won't
    get the padding benefit for that one query.
    '''
    if (not additional_records):
        udp_size, ext_rcode_flags, options = EDNS_DEFAULT_UDP_SIZE, long_pack(0), []
    else:
        parsed = _parse_single_opt_record(additional_records)
        if (parsed is None):
            return additional_records

        udp_size, ext_rcode_flags, options = parsed

    options = [[code, data] for code, data in options if code != EDNS_ECS_CODE]

    # +4 accounts for the padding option's own code/length header, which is part of the total we're rounding.
    unpadded_total = unpadded_len + 11 + sum(4 + len(data) for _, data in options) + 4
    remainder = unpadded_total % EDNS_PADDING_BLOCK
    pad_len = 0 if not remainder else EDNS_PADDING_BLOCK - remainder

    options.append([EDNS_PADDING_CODE, bytes(pad_len)])

    rdata = byte_join([double_short_pack(code, len(data)) + data for code, data in options])

    return byte_join([b'\x00', double_short_pack(DNS.OPT, udp_size), ext_rcode_flags, short_pack(len(rdata)), rdata])
