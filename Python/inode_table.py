import subprocess
import threading
import csv
import pandas as pd
import re
import pytsk3
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

image = "/dev/nbd0p2"  # à adapter
img = pytsk3.Img_Info(image)
fs = pytsk3.FS_Info(img)

output_csv = "inode_table.csv"
inode_list = []
inode_lock = threading.Lock()
csv_lock = threading.Lock()
threads = 8
counter = 0

# Récupération des inodes
print("[+] Running fls...")
try:
    fls_output = subprocess.check_output(["fls", "-r", "-p", "-o", "0", image], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
except Exception as e:
    print(f"[-] Failed to run fls: {e}")
    exit(1)

for line in fls_output.strip().splitlines():
    match = re.search(r'([0-9]+):\s+(.*)$', line)
    if match:
        inode = match.group(1)
        source_path = match.group(2)
        inode_list.append((inode, source_path))

# Init CSV
with open(output_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["inode", "deleted", "source_path", "ctime", "mtime", "atime"])
    for inode, source_path in inode_list:
        try:
            entry = fs.open_meta(inode=int(inode))
            deleted = not bool(entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
            ctime = entry.info.meta.crtime
            mtime = entry.info.meta.mtime
            atime = entry.info.meta.atime
            writer.writerow([inode, deleted, source_path, ctime, mtime, atime])
        except Exception as e:
            counter += 1
            continue
    print(counter)
df = pd.read_csv(output_csv)

for col in ['ctime', 'mtime', 'atime']:
    df[col] = pd.to_datetime(df[col], unit='s', errors='coerce')

df.to_csv("inode_table.csv", index=False)

print(f"[+] Done: {output_csv}")

