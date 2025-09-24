#!/usr/bin/env python3
"""
vt_check.py

Usage:
  python vt_check.py --api-key YOUR_API_KEY --hash <file_hash> --out output_basename \
      [--format json|csv] [--expand-engines]

Examples:
  python vt_check.py --api-key ABC123 --hash 44d88612fea8a8f36de82e1278abb02f --out report --format json
  python vt_check.py --api-key ABC123 --hash 44d886... --out report --format csv --expand-engines
"""

import argparse
import requests
import sys
import time
import json
import csv
from datetime import datetime

VT_FILES_ENDPOINT = "https://www.virustotal.com/api/v3/files/{}"

def pretty_ts(ts):
    if not ts:
        return ""
    try:
        return datetime.utcfromtimestamp(int(ts)).isoformat() + "Z"
    except Exception:
        return str(ts)

def query_vt(api_key: str, file_hash: str, max_retries=3, backoff=5):
    headers = {"x-apikey": api_key}
    url = VT_FILES_ENDPOINT.format(file_hash)
    for attempt in range(1, max_retries+1):
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            # not found
            return {"error": {"code": 404, "message": "Not found", "raw": resp.text}, "status_code": 404}
        elif resp.status_code == 429:
            # rate limited: wait and retry
            if attempt == max_retries:
                return {"error": {"code": 429, "message": "Rate limited, max retries reached", "raw": resp.text}, "status_code": 429}
            time.sleep(backoff * attempt)
            continue
        else:
            # other errors
            try:
                return {"error": {"code": resp.status_code, "message": resp.text}, "status_code": resp.status_code}
            except Exception:
                return {"error": {"code": resp.status_code, "message": "Unknown error"}, "status_code": resp.status_code}
    return {"error": {"message": "Failed after retries"}, "status_code": None}

def write_json(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def build_summary_row(data):
    # data is the full JSON from VT. Follow VT v3 structure: data['data']['attributes']
    row = {}
    d = data.get("data") or {}
    attrs = d.get("attributes", {})

    row["id"] = d.get("id", "")
    row["type"] = d.get("type", "")
    # common file ids/hashes
    row["md5"] = attrs.get("md5", "")
    row["sha1"] = attrs.get("sha1", "")
    row["sha256"] = attrs.get("sha256", "")
    row["size"] = attrs.get("size", "")
    row["type_description"] = attrs.get("type_description", "")
    # stats
    stats = attrs.get("last_analysis_stats", {})
    row["harmless"] = stats.get("harmless", 0)
    row["malicious"] = stats.get("malicious", 0)
    row["suspicious"] = stats.get("suspicious", 0)
    row["undetected"] = stats.get("undetected", 0)
    row["timeout"] = stats.get("timeout", 0)
    # reputation / total votes if present
    row["reputation"] = attrs.get("reputation", "")
    tv = attrs.get("total_votes", {})
    row["votes_harmless"] = tv.get("harmless", "")
    row["votes_malicious"] = tv.get("malicious", "")
    # dates
    row["first_submission_date"] = pretty_ts(attrs.get("first_submission_date"))
    row["last_submission_date"] = pretty_ts(attrs.get("last_submission_date"))
    row["last_analysis_date"] = pretty_ts(attrs.get("last_analysis_date"))
    # misc
    row["magic"] = attrs.get("magic", "")
    row["pe_info"] = json.dumps(attrs.get("pe_info", {}), ensure_ascii=False) if attrs.get("pe_info") else ""
    # permalink
    row["permalink"] = attrs.get("permalink", "")

    return row

def expand_engines_to_csv(data, csv_path):
    # produces one row per engine with engine name, category, result, method, engine_version
    d = data.get("data") or {}
    attrs = d.get("attributes", {})
    results = attrs.get("last_analysis_results", {}) or {}
    header = ["engine_name", "category", "method", "engine_version", "result", "id", "sha256"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        for engine_name, info in sorted(results.items()):
            writer.writerow([
                engine_name,
                info.get("category"),
                info.get("method"),
                info.get("engine_version"),
                info.get("result"),
                info.get("engine_additional_info", {}).get("id", ""),  # optional
                data.get("data", {}).get("id", "")
            ])

def main():
    parser = argparse.ArgumentParser(description="Interroger VirusTotal v3 pour un hash et sauver le résultat.")
    parser.add_argument("--api-key", required=True, help="Clé API VirusTotal (v3).")
    parser.add_argument("--hash", required=True, help="Hash du fichier (md5 / sha1 / sha256).")
    parser.add_argument("--out", required=True, help="Préfixe du fichier de sortie (ex: report -> report.json / report.csv).")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Format de sortie principal.")
    parser.add_argument("--expand-engines", action="store_true", help="Exporter un CSV détaillé par moteur (engines).")
    args = parser.parse_args()

    api_key = args.api_key.strip()
    file_hash = args.hash.strip()
    out_prefix = args.out.strip()

    print(f"[+] Querying VirusTotal for hash: {file_hash}")
    res = query_vt(api_key, file_hash)
    # if error object
    if "error" in res and res.get("status_code") not in (200,):
        print(f"[-] Error from VirusTotal: {res['error'].get('message')}. Status: {res.get('status_code')}")
        # still write raw for inspection
        write_json(res, out_prefix + ".json")
        print(f"[i] Raw response written to {out_prefix}.json")
        sys.exit(2)

    # save raw JSON always
    raw_json_path = out_prefix + ".json"
    write_json(res, raw_json_path)
    print(f"[+] Raw JSON saved to: {raw_json_path}")

    if args.format == "json":
        print("[+] Requested JSON output. (Raw saved above)")
        if args.expand_engines:
            engines_csv = out_prefix + "_engines.csv"
            expand_engines_to_csv(res, engines_csv)
            print(f"[+] Engines CSV saved to: {engines_csv}")
        print("[+] Done.")
        return

    # CSV summary
    if args.format == "csv":
        summary_csv = out_prefix + ".csv"
        header = [
            "id", "type", "md5", "sha1", "sha256", "size", "type_description",
            "harmless", "malicious", "suspicious", "undetected", "timeout",
            "reputation", "votes_harmless", "votes_malicious",
            "first_submission_date", "last_submission_date", "last_analysis_date",
            "magic", "pe_info", "permalink"
        ]
        row = build_summary_row(res)
        with open(summary_csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=header)
            writer.writeheader()
            writer.writerow({k: row.get(k, "") for k in header})
        print(f"[+] Summary CSV saved to: {summary_csv}")

        if args.expand_engines:
            engines_csv = out_prefix + "_engines.csv"
            expand_engines_to_csv(res, engines_csv)
            print(f"[+] Engines CSV saved to: {engines_csv}")

        print("[+] Done.")
        return

if __name__ == "__main__":
    main()

