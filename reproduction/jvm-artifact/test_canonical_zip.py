#!/usr/bin/env python3
"""Isolated grammar fixtures for the archive layer, not a full JAR inspector."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import zipfile
import zlib


def load(path, digest):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('codec source drift before import')
    spec = importlib.util.spec_from_file_location('reviewed_zip_codec', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fixture(entries, deflated=False, marker=False, body_transform=None, marker_at=0):
    """Independent minimal PKZIP fixture constructor; intentionally permits bad names."""
    local = bytearray(); central = bytearray()
    for ordinal, (name, data) in enumerate(entries):
        name = name.encode('ascii') if isinstance(name, str) else name
        extra = b'\xfe\xca\x00\x00' if marker and ordinal == marker_at else b''
        crc = zlib.crc32(data) & 0xffffffff
        if deflated:
            compressor = zlib.compressobj(wbits=-15)
            body = compressor.compress(data) + compressor.flush()
        else:
            body = data
        if body_transform is not None:
            body = body_transform(body)
        method = 8 if deflated else 0
        version = 20 if deflated else 10
        flags = 0x808 if deflated else 0x800
        offset = len(local)
        local += struct.pack('<4s5H3I2H', b'PK\x03\x04', version, flags, method, 0, 0x21,
                             0 if deflated else crc, 0 if deflated else len(body),
                             0 if deflated else len(data), len(name), len(extra))
        local += name + extra + body
        if deflated:
            local += struct.pack('<4I', 0x08074b50, crc, len(body), len(data))
        central += struct.pack('<4s6H3I5H2I', b'PK\x01\x02', version, version, flags,
                               method, 0, 0x21, crc, len(body), len(data), len(name),
                               len(extra), 0, 0, 0, 0, offset)
        central += name + extra
    eocd = struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, len(entries), len(entries),
                       len(central), len(local), 0)
    return bytes(local + central + eocd)


def field(raw, offset, fmt, value):
    data = bytearray(raw)
    struct.pack_into(fmt, data, offset, value)
    return bytes(data)


def run(module, out):
    out.mkdir(exist_ok=False)
    rows = []
    manifest = b'Manifest-Version: 1.0\r\nMain-Class: X\r\n\r\n'
    items = [('META-INF/MANIFEST.MF', manifest), ('X.class', b'PK\x03\x04data')]
    stored = fixture(items)
    compressed = fixture(items, deflated=True)
    cd = struct.unpack_from('<I', stored, len(stored)-6)[0]

    def check(label, raw, expected, canonical=False):
        try:
            archive = module.inspect_archive(raw, canonical=canonical)
            actual, code = True, None
        except module.ZipRejection as rejected:
            actual, code = False, rejected.code
        if actual != expected:
            raise AssertionError({'label':label,'expectedAccept':expected,'actualAccept':actual,'code':code})
        if actual:
            for entry in archive.entries:
                chunks = list(archive.iter_entry_chunks(entry, chunk_size=113))
                if any(len(c) > 113 for c in chunks):
                    raise AssertionError('chunk bound')
                content = b''.join(chunks)
                if len(content) != entry.uncompressed_size or zlib.crc32(content) & 0xffffffff != entry.crc32:
                    raise AssertionError('returned entry bytes')
        row = {'case': len(rows), 'label': label, 'expectedAccept': expected,
               'actualAccept': actual, 'code': code, 'bytes': len(raw),
               'sha256': hashlib.sha256(raw).hexdigest(), 'pass': actual == expected}
        rows.append(row)
        if actual != expected:
            raise AssertionError(row)

    check('stored-source', stored, True)
    check('stored-canonical', stored, True, True)
    check('deflate-source', compressed, True)
    check('deflate-canonical', compressed, True, True)
    check('jar-marker', fixture(items, True, True), True, True)
    check('directory-source', fixture([('d/', b''), ('d/x', b'1')]), True)
    check('deflated-empty-directory', fixture([('d/', b''), ('d/x', b'1')], True), True)
    reverse = fixture(items[::-1])
    check('source-unsorted', reverse, True)
    check('output-unsorted', reverse, False, True)
    dated = field(field(stored, 12, '<H', 0xffff), cd+14, '<H', 0xffff)
    check('source-opaque-date', dated, True)
    check('output-noncanonical-date', dated, False, True)
    large = fixture([('x', b'Z'*200000)], True)
    check('bounded-decompression', large, True)
    check('crc-all-ones', fixture([('x', b'\xff'*4)]), False)
    check('deflate-trailing', fixture([('x', b'a')], True, body_transform=lambda b:b+b'\x00'), False)
    check('deflate-truncated', fixture([('x', b'a')], True, body_transform=lambda b:b[:-1]), False)
    check('deflate-invalid', fixture([('x', b'a')], True, body_transform=lambda b:b'\x07'), False)
    oversize=fixture([('x',b'a'*20)],True)
    ocd=struct.unpack_from('<I',oversize,len(oversize)-6)[0]
    check('decompressed-exceeds-declaration',field(field(oversize,ocd+24,'<I',19),ocd-4,'<I',19),False)
    if module.MAX_ARCHIVE_BYTES != 1073741824: raise AssertionError('native 1GiB bound drift')
    check('declared-entry-over-native-1GiB',field(field(oversize,ocd+24,'<I',1073741825),ocd-4,'<I',1073741825),False)
    if rows[-1]['code']!='entry_too_large': raise AssertionError('entry bound not checked before decompression')
    native_bound=module.MAX_ARCHIVE_BYTES
    try:
        # Branch witness only: actual native 1GiB cumulative boundary is not exercised.
        module.MAX_ARCHIVE_BYTES=4096
        check('reduced-bound-cumulative-control',fixture([('a',b'Z'*2000),('b',b'Z'*2000)],True),True)
        check('reduced-bound-cumulative-overflow',fixture([('a',b'Z'*2000),('b',b'Z'*2000),('c',b'Z'*2000)],True),False)
        if rows[-1]['code']!='total_uncompressed_size_exceeded': raise AssertionError('cumulative bound branch')
    finally:
        module.MAX_ARCHIVE_BYTES=native_bound
    check('marker-on-second',fixture(items,marker=True,marker_at=1),False)
    marked=fixture(items,marker=True)
    mcd=struct.unpack_from('<I',marked,len(marked)-6)[0]
    check('forbidden-extra',field(field(marked,30+len(items[0][0]),'<H',1),mcd+46+len(items[0][0]),'<H',1),False)
    check('post-manifest-unsorted',fixture([items[0],('z',b''),('a',b'')]),False,True)
    gap=stored[:cd]+b'X'+stored[cd:]
    check('local-gap',field(gap,len(gap)-6,'<I',cd+1),False)
    first_cd_length=46+len(items[0][0])
    reordered=stored[:cd]+stored[cd+first_cd_length:-22]+stored[cd:cd+first_cd_length]+stored[-22:]
    check('central-order-mismatch',reordered,False)
    second_offset=struct.unpack_from('<I',stored,cd+first_cd_length+42)[0]
    check('local-overlap',field(stored,cd+first_cd_length+42,'<I',second_offset-1),False)

    negatives = [('prefix', b'X'+stored), ('suffix', stored+b'X'),
                 ('truncated-eocd', stored[:-1]), ('bad-eocd', field(stored,len(stored)-22,'<I',0)),
                 ('archive-comment', field(stored,len(stored)-2,'<H',1)),
                 ('multidisk', field(stored,len(stored)-18,'<H',1)),
                 ('count-mismatch', field(stored,len(stored)-14,'<H',1)),
                 ('count-sentinel', field(field(stored,len(stored)-14,'<H',65535),len(stored)-12,'<H',65535)),
                 ('cd-size', field(stored,len(stored)-10,'<I',1)),
                 ('cd-offset', field(stored,len(stored)-6,'<I',1)),
                 ('cd-size-sentinel', field(stored,len(stored)-10,'<I',0xffffffff)),
                 ('local-offset', field(stored,cd+42,'<I',1)),
                 ('local-signature', field(stored,0,'<I',0)),
                 ('central-signature', field(stored,cd,'<I',0)),
                 ('local-version-disagreement', field(stored,4,'<H',20)),
                 ('central-host', field(stored,cd+4,'<H',0x030a)),
                 ('internal-attributes', field(stored,cd+36,'<H',1)),
                 ('external-attributes', field(stored,cd+38,'<I',0x81a40000)),
                 ('entry-comment', field(stored,cd+32,'<H',1)),
                 ('entry-disk', field(stored,cd+34,'<H',1)),
                 ('timestamp-disagreement', field(stored,10,'<H',1)),
                 ('missing-utf8', field(field(stored,6,'<H',0),cd+8,'<H',0)),
                 ('encrypted', field(field(stored,6,'<H',0x801),cd+8,'<H',0x801)),
                 ('stored-descriptor-flag', field(field(stored,6,'<H',0x808),cd+8,'<H',0x808)),
                 ('unsupported-method', field(field(stored,8,'<H',9),cd+10,'<H',9)),
                 ('local-crc-disagreement', field(stored,14,'<I',0)),
                 ('central-crc-disagreement', field(stored,cd+16,'<I',0)),
                 ('size-sentinel', field(stored,cd+24,'<I',0xffffffff)),
                 ('crc-content', field(stored,30+len(items[0][0]),'<B',0)),
                 ('duplicate-name', fixture([('x',b'a'),('x',b'b')])),
                 ('casefold-collision', fixture([('x',b'a'),('X',b'b')])),
                 ('directory-with-content', fixture([('x/',b'a')]))]
    for name in (b'', b'/x', b'../x', b'x/../y', b'x//y', b'x\\y', b'x:y', b'x\x00y', b'x\x7fy', b'x\xffy', b'x'*241):
        negatives.append(('name-'+name.hex(), fixture([(name,b'a')])))
    dcd = struct.unpack_from('<I', compressed, len(compressed)-6)[0]
    compressed_size = struct.unpack_from('<I', compressed,dcd+20)[0]
    dd = 30 + len(items[0][0]) + compressed_size
    negatives += [('unsigned-descriptor', field(compressed,dd,'<I',0)),
                  ('descriptor-crc', field(compressed,dd+4,'<I',0)),
                  ('descriptor-size', field(compressed,dd+8,'<I',0)),
                  ('deflate-local-nonzero', field(compressed,14,'<I',1))]
    for label, raw in negatives:
        check(label, raw, False)

    # Writer is checked by both the independent stdlib reader and production parser.
    outputs = []
    for number in range(2):
        target = out/('canonical-%d.jar' % number)
        with target.open('xb') as stream:
            report = module.write_canonical(stream, items)
        raw = target.read_bytes()
        if raw != stored: raise AssertionError('writer differs from independent canonical fixture')
        aggregate=hashlib.sha256()
        for name,data in items:
            name_bytes=name.encode('ascii')
            aggregate.update(struct.pack('<H',len(name_bytes))+name_bytes)
            aggregate.update(struct.pack('<III',len(data),len(data),zlib.crc32(data)&0xffffffff))
        if (report.artifact_sha256!=hashlib.sha256(raw).hexdigest() or report.byte_size!=len(raw)
                or report.entry_count!=len(items) or report.total_uncompressed_size!=sum(len(data) for _,data in items)
                or report.entries_aggregate_sha256!=aggregate.hexdigest()):
            raise AssertionError('writer report mismatch')
        reader_report=module.inspect_archive(raw,canonical=True).report()
        if (reader_report.artifact_sha256!=report.artifact_sha256 or reader_report.entry_count!=report.entry_count
                or reader_report.total_uncompressed_size!=report.total_uncompressed_size
                or reader_report.entries_aggregate_sha256!=report.entries_aggregate_sha256):
            raise AssertionError('reader report mismatch')
        with zipfile.ZipFile(io.BytesIO(raw)) as jar:
            if [(name,jar.read(name)) for name in jar.namelist()] != items:
                raise AssertionError('stdlib copy replay')
        check('writer-roundtrip-'+str(number),raw,True,True)
        outputs.append(raw)
    if outputs[0] != outputs[1]: raise AssertionError('nondeterministic writer')
    for label, values in [('no-entries',[]), ('wrong-first',[('x',b'a')]),
                          ('directory-output',[('META-INF/MANIFEST.MF',manifest),('x/',b'')]),
                          ('unsorted-output',[('META-INF/MANIFEST.MF',manifest),('z',b''),('a',b'')]),
                          ('casefold-output',[('META-INF/MANIFEST.MF',manifest),('X',b''),('x',b'')]),
                          ('crc-sentinel-output',[('META-INF/MANIFEST.MF',manifest),('x',b'\xff'*4)]),
                          ('over-4096',[('META-INF/MANIFEST.MF',manifest)]+[(f'x{i:04}',b'') for i in range(4096)])]:
        stream=io.BytesIO()
        try: module.write_canonical(stream,values)
        except module.ZipRejection as rejected:
            if stream.tell()!=0: raise AssertionError('writer changed output before failed preflight')
            rows.append({'case':len(rows),'label':label,'pass':True,'code':rejected.code})
        else: raise AssertionError('writer accepted '+label)
    class ShortWriter(io.BytesIO):
        def write(self, data): return super().write(data[:3])
    partial = ShortWriter()
    partial_report = module.write_canonical(partial, items)
    if partial.getvalue() != stored or partial_report.artifact_sha256 != hashlib.sha256(stored).hexdigest():
        raise AssertionError('partial-write retry or digest')
    rows.append({'case':len(rows),'label':'writer-short-writes','pass':True})
    for response in (None, 0, -1, 'invalid', 99999999):
        class BadWriter(io.BytesIO):
            def write(self, data): return response
        try: module.write_canonical(BadWriter(), items)
        except OSError:
            rows.append({'case':len(rows),'label':'writer-no-progress-'+repr(response),'pass':True})
        else: raise AssertionError('writer falsely completed '+repr(response))
    with (out/'comparison.json').open('x') as stream:
        json.dump({'pass':True,'cases':len(rows),'rows':rows,
                   'scope':'ZIP grammar and copy-only writer primitives; not whole JAR/classfile inspection'},stream,sort_keys=True,indent=2)
    print(json.dumps({'pass':True,'cases':len(rows)}))


def mutants(path, digest, out):
    """Four independent one-fault mutants, each with its own decisive witness."""
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest: raise ValueError('source drift')
    original = raw.decode('utf-8')
    out.mkdir(exist_ok=False)
    crc_bad = fixture([('x',b'a')])
    crc_bad = field(crc_bad,31,'<B',ord('b'))
    tests = [
        ('crc', 'if (crc & 0xFFFFFFFF) != entry.crc32:', 'if False:', crc_bad),
        ('casefold', '        if folded in folded_names:\n            _reject("ascii_casefold_collision")\n        exact_names.add(raw_name)\n        folded_names.add(folded)\n        if compressed_size', '        if False:\n            _reject("ascii_casefold_collision")\n        exact_names.add(raw_name)\n        folded_names.add(folded)\n        if compressed_size', fixture([('x',b'a'),('X',b'b')])),
        ('eof', 'if not decompressor.eof:', 'if False:', fixture([('x',b'a')],True,body_transform=lambda b:b[:-1])),
        ('crc-sentinel', '        if crc32_value == 0xFFFFFFFF:\n            _reject("crc32_all_ones")\n        expected_made_by', '        if False:\n            _reject("crc32_all_ones")\n        expected_made_by', fixture([('x',b'\xff'*4)]))]
    rows=[]
    baseline=load(path,digest)
    for label, before, after, witness in tests:
        try: baseline.inspect_archive(witness)
        except baseline.ZipRejection: pass
        else: raise AssertionError('baseline accepted mutant witness '+label)
        if original.count(before)!=1: raise AssertionError('mutation anchor '+label)
        mutated=original.replace(before,after)
        target=out/(label+'.py')
        with target.open('x',encoding='utf-8',newline='\n') as stream: stream.write(mutated)
        mutant_hash=hashlib.sha256(target.read_bytes()).hexdigest()
        module=load(target,mutant_hash)
        module.inspect_archive(fixture([('x',b'a')]))
        try: module.inspect_archive(witness)
        except module.ZipRejection as exc: raise AssertionError('mutant survived: '+label+' '+exc.code)
        rows.append({'mutant':label,'detected':True,'sha256':mutant_hash,
                     'witnessSha256':hashlib.sha256(witness).hexdigest(),
                     'reason':'invalid isolated witness accepted by mutant; baseline rejects'})
    with (out/'comparison.json').open('x') as stream:
        json.dump({'pass':True,'mutants':rows},stream,sort_keys=True,indent=2)
    print(json.dumps({'pass':True,'mutantsDetected':len(rows)}))


if __name__=='__main__':
    if len(sys.argv) not in (4,5): raise SystemExit('usage: test_canonical_zip.py CODEC SHA256 OUT [mutants]')
    if len(sys.argv)==5:
        if sys.argv[4]!='mutants': raise SystemExit('invalid mode')
        mutants(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]))
    else:
        run(load(Path(sys.argv[1]),sys.argv[2]),Path(sys.argv[3]))
