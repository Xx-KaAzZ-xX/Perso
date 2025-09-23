#!/usr/bin/env python3
import os
import sys
import gzip
import re
import shutil

SYSLOG_RE_CLASSIC = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+')
ISO_SYSLOG_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?\s+')


def is_syslog_like(line, hostname):
    return hostname in line and (SYSLOG_RE_CLASSIC.match(line) or ISO_SYSLOG_RE.match(line))


def check_archive(path, hostname):
    try:
        with gzip.open(path, 'rt', encoding='utf-8', errors='ignore') as f:
            for _ in range(10):  # lire jusqu'à 10 lignes
                line = f.readline()
                if not line:
                    break
                if is_syslog_like(line, hostname):
                    return True
    except Exception:
        return False
    return False

def main(carved_dir, hostname, outdir):
    os.makedirs(outdir, exist_ok=True)
    count = 0
    for fname in os.listdir(carved_dir):
        path = os.path.join(carved_dir, fname)
        if not os.path.isfile(path) or not fname.endswith(".gz"):
            continue
        if check_archive(path, hostname):
            dst = os.path.join(outdir, fname)
            shutil.move(path, dst)  # garder l'original
            print(f"[+] Match: {fname}")
            count += 1
    print(f"\n[+] {count} archive(s) correspondant à {hostname if hostname else 'syslog-like'} copiée(s) dans {outdir}")

if __name__ == "__main__":
    if len(sys.argv) not in (3,4):
        print(f"Usage: {sys.argv[0]} <carved_dir> <hostname_or_- > <output_dir>")
        sys.exit(1)

    carved_dir = sys.argv[1]
    hostname_arg = sys.argv[2]
    outdir = sys.argv[3]
    hostname = None if hostname_arg == "-" else hostname_arg
    main(carved_dir, hostname, outdir)

