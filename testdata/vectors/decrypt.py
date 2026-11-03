"""Decrypt kurumi v1 files with pyhpke, independently of kurumi.

usage: python decrypt.py <private-key-hex> <file.kurumi>  (plaintext to stdout)
"""

import struct
import sys

from pyhpke import AEADId, CipherSuite, KDFId, KEMId


def decrypt(sk: bytes, data: bytes) -> bytes:
    assert len(sk) == 32
    info, enc, rest = data[:22], data[22:54], data[54:]
    assert info[:9] == b"KURUMI\0\0\x01" and info[9:15] == bytes.fromhex("002000010002")
    assert info[15] == 0, "this script handles compression 0x00 only"
    chunk, enc_len = struct.unpack(">IH", info[16:22])
    assert enc_len == 32
    suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
    ctx = suite.create_recipient_context(enc, suite.kem.deserialize_private_key(sk), info=info)
    out = bytearray()
    while True:
        flag, plen = rest[0], struct.unpack(">I", rest[1:5])[0]
        assert flag in (0, 1) and plen <= chunk and (flag == 1 or plen == chunk)
        out += ctx.open(rest[5 : 5 + plen + 16], aad=rest[:5])
        rest = rest[5 + plen + 16 :]
        if flag == 1:
            assert not rest, "trailing data"
            return bytes(out)


if __name__ == "__main__":
    with open(sys.argv[2], "rb") as f:
        sys.stdout.buffer.write(decrypt(bytes.fromhex(sys.argv[1]), f.read()))
