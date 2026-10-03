#!/usr/bin/env python3
"""LIBYAM header obfuscator (length-preserving)."""
import pathlib
import re
import sys

REPLACEMENTS = [
    (rb'(?<![A-Za-z0-9])frida', b'yamfl'),
    (rb'(?<![A-Za-z0-9])Frida', b'Yamfl'),
    (rb'(?<![A-Za-z0-9])FRIDA', b'YAMFL'),
    (rb'(?<![A-Za-z0-9])gum',   b'yam'),
    (rb'(?<![A-Za-z0-9])Gum',   b'Yam'),
    (rb'(?<![A-Za-z0-9])GUM',   b'YAM'),
]

def obfuscate_header(path):
    p = pathlib.Path(path)
    data = p.read_bytes()
    orig = len(data)
    for pattern, repl in REPLACEMENTS:
        data = re.sub(pattern, repl, data)

    # Fix .c example includes (post-obfuscation names -> on-disk names)
    if path.endswith('.c'):
        data = data.replace(b'#include "yamfl-yamjs.h"', b'#include "YAMJS.h"')
        data = data.replace(b'#include "yamfl-yam.h"',   b'#include "YAM.h"')
        data = data.replace(b'#include <yamfl-yamjs.h>', b'#include "YAMJS.h"')
        data = data.replace(b'#include <yamfl-yam.h>',   b'#include "YAM.h"')

    # Fix .hpp includes: umbrella + filenames on disk are unchanged
    if path.endswith('.hpp'):
        data = data.replace(b'#include <yam/yam.h>',      b'#include "YAM.h"')
        data = data.replace(b'#include <gum/gum.h>',      b'#include "YAM.h"')
        data = data.replace(b'#include <glib.h>',         b'#include "YAM.h"')
        data = data.replace(b'#include <glib-object.h>',  b'#include "YAM.h"')
        data = data.replace(b'"yampp.hpp"',               b'"gumpp.hpp"')

    p.write_bytes(data)
    print(f"  {path}: {orig} -> {len(data)} bytes")

if __name__ == '__main__':
    for path in sys.argv[1:]:
        try:
            obfuscate_header(path)
        except Exception as ex:
            print(f"FAILED {path}: {ex}")
