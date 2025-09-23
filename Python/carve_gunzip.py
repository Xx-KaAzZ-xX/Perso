#!/usr/bin/env python3
import sys
import os
import zlib
import binascii
import fcntl
import struct

MAGIC = b"\x1f\x8b\x08"
CHUNK_SIZE = 64 * 1024
MAX_GZIP_SIZE = 5 * 1024**3  # 5 Go max
BLKGETSIZE64 = 0x80081272  # ioctl pour block devices

def get_device_size(path):
    try:
        with open(path, 'rb') as f:
            size = fcntl.ioctl(f.fileno(), BLKGETSIZE64, b'\0'*8)
            return struct.unpack('Q', size)[0]
    except:
        return os.path.getsize(path)

def print_progress(current, total):
    if total == 0:
        return
    percent = current / total * 100
    bar_len = 40
    filled_len = int(bar_len * percent // 100)
    bar = "=" * filled_len + "-" * (bar_len - filled_len)
    current_gb = current / 1e9
    total_gb = total / 1e9
    print(f"\rProgress: [{bar}] {percent:.2f}% ({current_gb:.2f} / {total_gb:.2f} GB)", end='')

def carve_gzip(image_path, outdir):
    total_size = get_device_size(image_path)
    print(f"[+] Taille totale détectée : {total_size / 1e9:.2f} GB")
    pos = 0
    count = 0

    with open(image_path, "rb") as f:
        while True:
            f.seek(pos)
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            idx = chunk.find(MAGIC)
            if idx == -1:
                pos += len(chunk) - len(MAGIC)
                print_progress(pos, total_size)
                continue

            start_offset = pos + idx
            f.seek(start_offset)
            #print(f"\n[+] Header trouvé à l’offset {start_offset}")

            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            crc32_calc = 0
            isize_calc = 0
            compressed_chunks = []

            try:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    compressed_chunks.append(chunk)
                    out = d.decompress(chunk)
                    crc32_calc = binascii.crc32(out, crc32_calc) & 0xFFFFFFFF
                    isize_calc = (isize_calc + len(out)) & 0xFFFFFFFF

                    if d.unused_data:
                        # fin du member atteinte
                        consumed = sum(len(c) for c in compressed_chunks) - len(d.unused_data)
                        # footer
                        if len(d.unused_data) >= 8:
                            footer = d.unused_data[:8]
                        else:
                            footer = d.unused_data + f.read(8 - len(d.unused_data))

                        crc32_footer = int.from_bytes(footer[:4], 'little')
                        isize_footer = int.from_bytes(footer[4:], 'little')

                        member_size = consumed + 8

                        # concaténer et écrire le member complet
                        compressed_member = b''.join(compressed_chunks)[:consumed] + footer
                        out_file_path = os.path.join(outdir, f"carved_{count+1}.gz")
                        with open(out_file_path, "wb") as out_f:
                            out_f.write(compressed_member)

                        count += 1
                        #print(f"[+] Fichier extrait : {out_file_path}")
                        pos = start_offset + member_size
                        break

                print_progress(pos, total_size)

            except Exception as e:
                #print(f"[-] Erreur à l’offset {start_offset}: {e}")
                pos = start_offset + len(MAGIC)
                print_progress(pos, total_size)

    print(f"\n[+] Extraction terminée, {count} fichier(s) gzip extrait(s)")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <image/partition> <output_dir>")
        sys.exit(1)

    image_path = sys.argv[1]
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    carve_gzip(image_path, outdir)

