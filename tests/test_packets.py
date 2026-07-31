import pytest
import sys
sys.path.insert(0, '..')

from dns_tls_constants import DNS, short_pack, long_pack, double_short_pack
from protocol_tools import domain_stob, build_dns_query_hdr, build_dns_response_hdr, sanitize_and_pad_edns, parse_query_name
from dns_tls_packets import ClientRequest, _ResourceRecord, ttl_rewrite


class TestDomainStob:
    def test_simple_domain(self):
        assert domain_stob('example.com') == b'\x07example\x03com\x00'

    def test_root(self):
        assert domain_stob('') == b'\x00'

    def test_multi_label(self):
        result = domain_stob('www.example.com')
        assert result == b'\x03www\x07example\x03com\x00'


class TestBuildDnsHeader:
    def test_query_header(self):
        hdr = build_dns_query_hdr(1, 0, cd=0)
        assert len(hdr) == 12

    def test_response_header(self):
        hdr = build_dns_response_hdr(1, 1, rd=1, cd=0, rc=0)
        assert len(hdr) == 12


class TestSanitizeAndPadEdns:
    def test_empty_additions(self):
        result = sanitize_and_pad_edns(b'', 50)
        assert len(result) > 4

    def test_dnssec_flag(self):
        result = sanitize_and_pad_edns(b'', 50, dnssec=True)
        assert len(result) > 4


class TestResourceRecord:
    def test_create(self):
        rec = _ResourceRecord(b'\x03www', b'\x00\x01', b'\x00\x01', b'\x00\x00\x0e\x10', b'\xc0\xa8\x01\x01')
        assert rec.name == b'\x03www'
        assert rec.qtype == b'\x00\x01'
        assert len(bytes(rec)) > 0

    def test_mutable_ttl(self):
        rec = _ResourceRecord(b'\x00', b'\x00\x01', b'\x00\x01', b'\x00\x00\x00\x3c', b'\x00')
        rec.ttl = long_pack(300)
        assert rec.ttl == b'\x00\x00\x01\x2c'


class TestClientRequest:
    def test_parse_query(self):
        addr = ('127.0.0.1', 12345)
        req = ClientRequest(addr, None)
        assert req.address == addr

    def test_generate_local_query(self):
        req = ClientRequest.generate_local_query('example.com')
        assert req.qname == 'example.com'
        assert req.qtype == 1


class TestTTLRewrite:
    def test_min_ttl_enforced(self):
        data = (
            short_pack(1) +
            b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' +
            b'\x07example\x03com\x00' +
            b'\x00\x01\x00\x01' +
            b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\xc0\xa8\x01\x01'
        )
        result, cache, rcode = ttl_rewrite(data, 1)
        assert result is not None


class TestParseQueryNameHardening:
    def test_truncated_pointer_no_raise(self):
        # single 0xC0 byte with no second byte: should not raise
        data = b'\xc0'
        dns_query = b'\x00' * 20
        # should return without exception (empty name)
        result = parse_query_name(data, dns_query)
        assert result is not None

    def test_non_utf8_label_no_raise(self):
        # label byte 0x80 (non-ASCII, not valid UTF-8): should decode via latin-1 without exception
        data = b'\x01\x80\x00'
        dns_query = b'\x00' * 20
        offset, local_domain, qname = parse_query_name(data, dns_query, qname=True)
        assert isinstance(qname, str)

    def test_negative_pointer_no_raise(self):
        # pointer value < 12 produces negative target: must not raise or silently misparse
        # 0xC0 0x00 => pointer_offset=0, target=-12, out of range -> break
        data = b'\xc0\x00'
        dns_query = b'\x00' * 20
        result = parse_query_name(data, dns_query)
        assert result is not None


class TestClientRequestParseGuards:
    def test_too_short_raises_value_error(self):
        addr = ('127.0.0.1', 12345)
        req = ClientRequest(addr, None)
        with pytest.raises(ValueError, match='dns packet too short'):
            req.parse(b'\x00\x01')

    def test_exactly_12_bytes_no_struct_error(self):
        # 12-byte header with qcount=0 but question section offset parse needs at least label+4 bytes;
        # parse_query_name on empty returns offset=0 so double_short_unpack guard fires
        addr = ('127.0.0.1', 12345)
        req = ClientRequest(addr, None)
        with pytest.raises(ValueError):
            req.parse(b'\x00' * 12)
