"""Synthetic intake boundary tests. No GitHub calls, keys, auth tokens or filing."""
from dataclasses import dataclass
import base64
import hashlib
import unittest

MAX_CHUNKS = 48
MAX_BYTES = 1_536_000
CHUNK_BYTES = 32_000

@dataclass(frozen=True)
class Enrollment:
    author_id: int
    device_key_id: str
    revoked: bool = False

@dataclass(frozen=True)
class Chunk:
    author_id: int
    package_id: str
    index: int
    count: int
    ciphertext_sha256: str
    data: str
    edited: bool = False

@dataclass(frozen=True)
class Manifest:
    author_id: int
    package_id: str
    device_key_id: str
    count: int
    ciphertext_bytes: int
    ciphertext_sha256: str
    expires_at: int
    committed: bool
    edited: bool = False

class Reject(ValueError):
    pass

def validate(manifest: Manifest, chunks: list[Chunk], enrollment: Enrollment,
             consumed: set[str], now: int) -> bytes:
    # This is transport validation, not cryptographic proof or permission to file.
    if enrollment.revoked or enrollment.author_id != manifest.author_id:
        raise Reject('not enrolled')
    if enrollment.device_key_id != manifest.device_key_id:
        raise Reject('wrong device')
    if manifest.package_id in consumed or not manifest.committed or manifest.edited:
        raise Reject('consumed/incomplete/edited')
    if manifest.expires_at <= now or manifest.expires_at > now + 86400:
        raise Reject('expired or excessive validity')
    if not 1 <= manifest.count <= MAX_CHUNKS or len(chunks) != manifest.count:
        raise Reject('count')
    if not 1 <= manifest.ciphertext_bytes <= MAX_BYTES:
        raise Reject('size')
    if len(manifest.ciphertext_sha256) != 64 or any(c not in '0123456789abcdef' for c in manifest.ciphertext_sha256):
        raise Reject('digest format')
    if {c.index for c in chunks} != set(range(manifest.count)):
        raise Reject('missing or duplicate')
    pieces: list[bytes] = []
    for chunk in sorted(chunks, key=lambda c: c.index):
        if (chunk.author_id != manifest.author_id or chunk.package_id != manifest.package_id or
            chunk.count != manifest.count or chunk.ciphertext_sha256 != manifest.ciphertext_sha256 or chunk.edited):
            raise Reject('mixed or edited input')
        if len(chunk.data) > 42668:
            raise Reject('chunk size')
        try:
            piece = base64.b64decode(chunk.data, validate=True)
        except Exception as failure:
            raise Reject('encoding') from failure
        if not 1 <= len(piece) <= CHUNK_BYTES:
            raise Reject('chunk byte size')
        pieces.append(piece)
    blob = b''.join(pieces)
    if len(blob) != manifest.ciphertext_bytes or hashlib.sha256(blob).hexdigest() != manifest.ciphertext_sha256:
        raise Reject('integrity')
    return blob

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.blob = b'synthetic ciphertext placeholder'
        digest = hashlib.sha256(self.blob).hexdigest()
        self.enrollment = Enrollment(101, 'synthetic-device-a')
        self.manifest = Manifest(101, 'synthetic-id', 'synthetic-device-a', 1, len(self.blob), digest, 2000, True)
        self.chunk = Chunk(101, 'synthetic-id', 0, 1, digest, base64.b64encode(self.blob).decode())
    def run_case(self, manifest=None, chunks=None, enrollment=None, consumed=None, now=1000):
        return validate(manifest or self.manifest, chunks or [self.chunk], enrollment or self.enrollment,
                        consumed or set(), now)
    def changed(self, obj, **kw):
        from dataclasses import replace
        return replace(obj, **kw)
    def test_complete_enrolled_package(self):
        self.assertEqual(self.blob, self.run_case())
    def test_claimed_sender_and_revoked_device(self):
        for e in [Enrollment(999, 'synthetic-device-a'), Enrollment(101, 'other'), Enrollment(101, 'synthetic-device-a', True)]:
            with self.assertRaises(Reject): self.run_case(enrollment=e)
    def test_shared_github_account_does_not_merge_devices(self):
        with self.assertRaises(Reject): self.run_case(enrollment=Enrollment(101, 'synthetic-device-b'))
    def test_uncommitted_edited_expired_or_consumed(self):
        for m in [self.changed(self.manifest, committed=False), self.changed(self.manifest, edited=True),
                  self.changed(self.manifest, expires_at=1000), self.changed(self.manifest, expires_at=90000)]:
            with self.assertRaises(Reject): self.run_case(manifest=m)
        with self.assertRaises(Reject): self.run_case(consumed={'synthetic-id'})
    def test_cross_author_package_or_edited_chunk(self):
        for c in [self.changed(self.chunk, author_id=999), self.changed(self.chunk, package_id='other'),
                  self.changed(self.chunk, edited=True), self.changed(self.chunk, count=2)]:
            with self.assertRaises(Reject): self.run_case(chunks=[c])
    def test_duplicate_missing_and_oversized(self):
        for m,cs in [(self.changed(self.manifest,count=2),[self.chunk,self.chunk]),
                     (self.changed(self.manifest,count=2),[self.chunk]),
                     (self.changed(self.manifest,ciphertext_bytes=MAX_BYTES+1),[self.chunk])]:
            with self.assertRaises(Reject): self.run_case(manifest=m,chunks=cs)
    def test_encoding_digest_and_length(self):
        for c in [self.changed(self.chunk,data='not base64!'), self.changed(self.chunk,data='A'*43000),
                  self.changed(self.chunk,data=base64.b64encode(b'changed').decode())]:
            with self.assertRaises(Reject): self.run_case(chunks=[c])
        with self.assertRaises(Reject): self.run_case(manifest=self.changed(self.manifest,ciphertext_bytes=1))
    def test_validation_does_not_consume_or_file(self):
        consumed: set[str] = set()
        validate(self.manifest,[self.chunk],self.enrollment,consumed,1000)
        self.assertEqual(set(),consumed)

if __name__ == '__main__':
    unittest.main()
