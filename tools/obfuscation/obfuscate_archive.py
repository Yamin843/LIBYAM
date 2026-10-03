#!/usr/bin/env python3
"""LIBYAM post-build obfuscator — safe sections only.

Never touches .symtab/.dynsym (binary Elf64_Sym entries).
Uses llvm-ar for V8-scale archives.
"""
import sys
import os
import struct
import subprocess
import tempfile
import shutil


AR_MAGIC = b'!<arch>\n'
AR_HEADER_SIZE = 60
AR_END = b'`\n'


def parse_ar(data):
    if data[:8] != AR_MAGIC:
        raise ValueError("Not an ar archive")
    pos = 8
    strtab = None
    while pos + AR_HEADER_SIZE <= len(data):
        header = data[pos:pos + AR_HEADER_SIZE]
        if header[58:60] != AR_END:
            break
        name = header[0:16].rstrip(b' ').decode('ascii', 'replace')
        try:
            size = int(header[48:58].decode('ascii').strip())
        except ValueError:
            break
        data_offset = pos + AR_HEADER_SIZE
        data_end = data_offset + size

        if name == '//':
            strtab = data[data_offset:data_end]
        elif name.startswith('/') and name[1:].isdigit() and strtab is not None:
            off = int(name[1:])
            end = strtab.find(b'/\n', off)
            if end < 0:
                end = strtab.find(b'\n', off)
            if end < 0:
                end = len(strtab)
            actual = strtab[off:end].decode('ascii', 'replace').rstrip('/')
            yield (actual, data_offset, size, pos, header[16:48])
        else:
            yield (name.rstrip('/'), data_offset, size, pos, header[16:48])

        pos = data_end + (size & 1)


import re

def _replace_prefix(data, old, new):
    # Match `old` only when preceded by a non-alphanumeric byte (start of string,
    # underscore, dot, dash, slash, space, etc.). This protects English words
    # like `argument` (contains `gum`) and `Fridays` (contains `frida`).
    pattern = rb'(?<![A-Za-z0-9])' + re.escape(old)
    return re.sub(pattern, new, data)

def apply_replacements(data):
    data = _replace_prefix(data, b'frida', b'yamfl')
    data = _replace_prefix(data, b'Frida', b'Yamfl')
    data = _replace_prefix(data, b'FRIDA', b'YAMFL')
    data = _replace_prefix(data, b'gum', b'yam')
    data = _replace_prefix(data, b'Gum', b'Yam')
    data = _replace_prefix(data, b'GUM', b'YAM')
    return data


def patch_object(path):
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except Exception:
        return 0
    if raw[:4] != b'\x7fELF' or raw[4] != 2:
        return 0
    data = bytearray(raw)

    try:
        e_shoff     = struct.unpack_from('<Q', data, 0x28)[0]
        e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
        e_shnum     = struct.unpack_from('<H', data, 0x3c)[0]
        e_shstrndx  = struct.unpack_from('<H', data, 0x3e)[0]
    except struct.error:
        return 0
    if not e_shoff or not e_shnum or e_shentsize == 0:
        return 0

    try:
        shstr_hdr = e_shoff + e_shstrndx * e_shentsize
        shstr_off = struct.unpack_from('<Q', data, shstr_hdr + 0x18)[0]
        shstr_sz  = struct.unpack_from('<Q', data, shstr_hdr + 0x20)[0]
    except struct.error:
        return 0
    if shstr_off + shstr_sz > len(data):
        return 0
    shstrtab = bytes(data[shstr_off:shstr_off + shstr_sz])

    SHT_PROGBITS = 1
    SHT_STRTAB   = 3

    modified = 0
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        if sh + 0x40 > len(data):
            break
        try:
            sh_name   = struct.unpack_from('<I', data, sh + 0)[0]
            sh_type   = struct.unpack_from('<I', data, sh + 4)[0]
            sh_offset = struct.unpack_from('<Q', data, sh + 0x18)[0]
            sh_size   = struct.unpack_from('<Q', data, sh + 0x20)[0]
        except struct.error:
            continue
        if not sh_size or not sh_offset:
            continue
        if sh_offset + sh_size > len(data):
            continue

        e = shstrtab.find(b'\x00', sh_name)
        if e < 0:
            continue
        secname = shstrtab[sh_name:e]

        # Skip binary/metadata sections
        if secname in (b'.symtab', b'.dynsym', b'.shstrtab',
                       b'.comment', b'.note.gnu.build-id'):
            continue
        if secname.startswith(b'.note.') or secname.startswith(b'.debug'):
            continue

        should_patch = False
        if sh_type == SHT_STRTAB:
            should_patch = True
        elif sh_type == SHT_PROGBITS:
            if (secname.startswith(b'.rodata') or
                secname == b'.data' or
                secname.startswith(b'.data.rel') or
                secname == b'.sdata'):
                should_patch = True

        if not should_patch:
            continue

        seg = bytes(data[sh_offset:sh_offset + sh_size])
        new = apply_replacements(seg)
        if new != seg:
            diff = sum(1 for a, b in zip(seg, new) if a != b)
            data[sh_offset:sh_offset + sh_size] = new
            modified += diff

    if modified:
        with open(path, 'wb') as f:
            f.write(data)
    return modified


def strip_debug(path):
    for cmd in (
        ['llvm-objcopy', '--strip-debug', path],
        ['llvm-strip', '--strip-debug', path],
        ['llvm-strip', '--strip-unneeded', path],
        ['objcopy', '--strip-debug', path],
        ['strip', '--strip-debug', path],
        ['strip', '--strip-unneeded', path],
    ):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if r.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception:
            continue
    return False


def rename_member(name):
    import re
    for old, new in [(r'(?<![A-Za-z0-9])frida', 'yamfl'),
                     (r'(?<![A-Za-z0-9])Frida', 'Yamfl'),
                     (r'(?<![A-Za-z0-9])FRIDA', 'YAMFL'),
                     (r'(?<![A-Za-z0-9])gum', 'yam'),
                     (r'(?<![A-Za-z0-9])Gum', 'Yam'),
                     (r'(?<![A-Za-z0-9])GUM', 'YAM')]:
        name = re.sub(old, new, name)
    return name


def build_archive(tmp, archive, names):
    new_archive = os.path.join(tmp, '_out.a')
    for ar_tool in ('llvm-ar', 'llvm-ar-14', 'llvm-ar-15'):
        try:
            r = subprocess.run(
                [ar_tool, 'rcs', new_archive] + names,
                cwd=tmp, capture_output=True, text=True, timeout=1800
            )
            if r.returncode == 0:
                print("  archive created with %s (%d members)" % (ar_tool, len(names)))
                return new_archive
            else:
                print("  %s failed: %s" % (ar_tool, r.stderr.strip()[:200]))
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            print("  %s timed out" % ar_tool)
            continue

    print("  trying GNU ar in batches...")
    if os.path.exists(new_archive):
        os.remove(new_archive)
    with open(new_archive, 'wb') as f:
        f.write(b'!<arch>\n')

    BATCH = 50
    for i in range(0, len(names), BATCH):
        batch = names[i:i + BATCH]
        try:
            r = subprocess.run(
                ['ar', 'q', new_archive] + batch,
                cwd=tmp, capture_output=True, text=True, timeout=600
            )
            if r.returncode != 0:
                print("  batch %d failed: %s" % (i // BATCH, r.stderr.strip()[:200]))
                return None
        except subprocess.TimeoutExpired:
            print("  batch %d timed out" % (i // BATCH))
            return None

    try:
        subprocess.run(['ranlib', new_archive], cwd=tmp,
                       capture_output=True, timeout=3600)
    except Exception:
        pass
    return new_archive


def obfuscate_archive(archive):
    if not os.path.exists(archive):
        print("  SKIP (not found): %s" % archive)
        return

    print("=== %s ===" % archive)
    orig_size = os.path.getsize(archive)

    with open(archive, 'rb') as f:
        raw = f.read()

    try:
        members = list(parse_ar(raw))
    except ValueError as e:
        print("  ERROR: %s" % e)
        return

    print("  total members: %d" % len(members))

    tmp = tempfile.mkdtemp(prefix='yam_obf_')
    try:
        extracted = []
        for idx, (name, offset, size, hdr_off, meta) in enumerate(members):
            if not name.endswith(('.o', '.obj')):
                continue
            safe = "%05d_%s" % (idx, os.path.basename(name).replace('/', '_'))
            obj_path = os.path.join(tmp, safe)
            with open(obj_path, 'wb') as f:
                f.write(raw[offset:offset + size])
            extracted.append((idx, name, safe, obj_path))

        print("  extracted %d object files" % len(extracted))
        if not extracted:
            print("  no objects — skipping")
            return

        stripped = 0
        for _, _, _, p in extracted:
            if strip_debug(p):
                stripped += 1
        print("  stripped debug from %d/%d objects" % (stripped, len(extracted)))

        total = 0
        for _, _, _, p in extracted:
            total += patch_object(p)
        print("  %d bytes replaced across %d objects" % (total, len(extracted)))

        used = set()
        rename_map = []
        renamed = 0
        for idx, orig, safe, p in extracted:
            new_name = rename_member(orig)
            if new_name != orig:
                renamed += 1
            base = new_name
            while base in used:
                base = "_" + base
            used.add(base)
            final_p = os.path.join(tmp, base)
            os.rename(p, final_p)
            rename_map.append(base)
        print("  renamed %d archive members" % renamed)

        new_archive = build_archive(tmp, archive, rename_map)
        if new_archive is None or not os.path.exists(new_archive):
            print("  ERROR: failed to build new archive")
            return

        new_size = os.path.getsize(new_archive)
        print("  new size: %d bytes (was %d)" % (new_size, orig_size))

        try:
            os.replace(new_archive, archive)
        except OSError:
            shutil.copyfile(new_archive, archive)

    except Exception as ex:
        print("  EXCEPTION: %s" % ex)
        import traceback
        traceback.print_exc()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    for path in sys.argv[1:]:
        try:
            obfuscate_archive(path)
        except Exception as ex:
            print("FAILED for %s: %s" % (path, ex))
