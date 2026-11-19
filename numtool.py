#!/usr/bin/env python3
"""numtool - phone number OSINT toolkit."""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

VERSION = "2.0"
UA = "numtool/%s" % VERSION
CFG = Path.home() / ".config" / "numtool"
CACHE = Path.home() / ".cache" / "numtool"
CFG.mkdir(parents=True, exist_ok=True)
CACHE.mkdir(parents=True, exist_ok=True)

COLOR = True


def c(code, s):
    return s if not COLOR else "\033[%sm%s\033[0m" % (code, s)


def g(s): return c("32", s)
def y(s): return c("33", s)
def r(s): return c("31", s)
def cy(s): return c("36", s)
def dim(s): return c("90", s)


def load_keys():
    f = CFG / "keys.env"
    if f.exists():
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("\"'"))


def http_json(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# ---------------- local ----------------

def local_info(e164):
    n = phonenumbers.parse(e164, None)
    return {
        "valid": phonenumbers.is_valid_number(n),
        "possible": phonenumbers.is_possible_number(n),
        "country": geocoder.country_name_for_number(n, "en") or "",
        "region": geocoder.description_for_number(n, "en") or "",
        "carrier": carrier.name_for_number(n, "en") or "",
        "line_type": str(phonenumbers.number_type(n)).split(".")[-1],
        "timezones": list(timezone.time_zones_for_number(n)),
        "cc": n.country_code,
        "carrier_code": n.preferred_domestic_carrier_code or "",
        "e164": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164),
        "national": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.NATIONAL),
        "rfc3966": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.RFC3966),
        "international": phonenumbers.format_number(
            n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
    }


# ---------------- scanners ----------------

def scan_dorks(e164, num):
    q = urllib.parse.quote('"%s"' % e164)
    return {
        "google": "https://www.google.com/search?q=" + q,
        "bing": "https://www.bing.com/search?q=" + q,
        "duckduckgo": "https://duckduckgo.com/?q=" + q,
        "google_files": "https://www.google.com/search?q=%s+filetype:pdf" % q,
    }


SOCIAL = {
    "truecaller": "https://www.truecaller.com/search/in/%s",
    "whatsapp": "https://wa.me/%s",
    "telegram": "https://t.me/+%s",
    "facebook": "https://www.facebook.com/search/top?q=%s",
    "instagram": "https://www.instagram.com/%s/",
    "linkedin": "https://www.linkedin.com/search/results/all/?keywords=%s",
    "twitter": "https://twitter.com/search?q=%s",
    "github": "https://github.com/search?q=%s",
    "olx": "https://www.olx.in/items/q-%s",
    "quikr": "https://www.quikr.com/q/%s",
}


def scan_social(e164, num):
    return {k: v % num for k, v in SOCIAL.items()}


def scan_numverify(e164, num):
    return http_json("http://apilayer.net/api/validate?" + urllib.parse.urlencode(
        {"access_key": os.environ["NUMVERIFY_KEY"], "number": num}))


def scan_veriphone(e164, num):
    return http_json("https://api.veriphone.io/v2/verify?" + urllib.parse.urlencode(
        {"phone": e164, "key": os.environ["VERIPHONE_KEY"]}))


def scan_abstract(e164, num):
    return http_json("https://phonevalidation.abstractapi.com/v1/?" + urllib.parse.urlencode(
        {"api_key": os.environ["ABSTRACT_KEY"], "phone": e164}))


def scan_ipqs(e164, num):
    return http_json("https://ipqualityscore.com/api/json/phone/%s/%s" % (
        os.environ["IPQS_KEY"], e164))


def scan_googlecse(e164, num):
    data = http_json("https://www.googleapis.com/customsearch/v1?" + urllib.parse.urlencode(
        {"key": os.environ["GOOGLE_KEY"], "cx": os.environ["GOOGLE_CX"],
         "q": '"%s"' % e164, "num": 10}))
    return {
        "total": data.get("searchInformation", {}).get("totalResults", "0"),
        "hits": [{"title": i.get("title"), "link": i.get("link")}
                 for i in data.get("items", [])],
    }


def scan_geo(e164, num, region=""):
    if not region:
        return {"skipped": "no region"}
    data = http_json("https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode(
        {"q": region, "format": "json", "limit": 1}))
    if not data:
        return {"skipped": "not found"}
    lat, lon = data[0]["lat"], data[0]["lon"]
    return {"display": data[0].get("display_name"),
            "map": "https://maps.google.com/?q=%s,%s" % (lat, lon)}


SCANNERS = {
    "dorks":   (scan_dorks, None, False),
    "social":  (scan_social, None, False),
    "geo":     (scan_geo, None, True),
    "numverify": (scan_numverify, "NUMVERIFY_KEY", True),
    "veriphone": (scan_veriphone, "VERIPHONE_KEY", True),
    "abstract": (scan_abstract, "ABSTRACT_KEY", True),
    "ipqs":    (scan_ipqs, "IPQS_KEY", True),
    "googlecse": (scan_googlecse, "GOOGLE_KEY", True),
}


# ---------------- cache ----------------

def cpath(e164, name):
    h = hashlib.sha256(("%s|%s" % (e164, name)).encode()).hexdigest()[:16]
    return CACHE / ("%s.json" % h)


def cached(e164, name, fn, use_cache):
    p = cpath(e164, name)
    if use_cache and p.exists() and time.time() - p.stat().st_mtime < 86400:
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    out = fn(e164, e164.lstrip("+"))
    if isinstance(out, dict):
        p.write_text(json.dumps(out))
    return out


# ---------------- output ----------------

def render(data, quiet=False):
    loc = data["local"]
    head = g("[+] ") + loc["e164"] if loc["valid"] else r("[!] ") + "invalid " + data["query"]
    print("\n" + head)
    if not quiet:
        for k in ("country", "region", "carrier", "line_type", "timezones",
                  "international", "rfc3966"):
            v = loc[k]
            print("  %s %s" % (y("%-12s" % k), ", ".join(v) if isinstance(v, list) else (v or "-")))
        if loc["carrier_code"]:
            print("  %s %s" % (y("%-12s" % "carrier_code"), loc["carrier_code"]))
    for name, res in data["scanners"].items():
        print("\n" + cy("[%s]" % name))
        if isinstance(res, dict):
            for k, v in res.items():
                if isinstance(v, list):
                    for item in v:
                        print("  " + dim(str(item)))
                else:
                    print("  %s %s" % (y("%-14s" % k), v))


def one_line(data):
    loc = data["local"]
    ok = g("OK ") if loc["valid"] else r("BAD")
    print("%s %-16s %-12s %-14s %s" % (
        ok, loc["e164"], loc["carrier"] or "-", loc["region"] or "-",
        ",".join(loc["timezones"]) or "-"))


# ---------------- main ----------------

def run(number, picked, args):
    if not number.startswith("+"):
        number = "+" + number
    try:
        local = local_info(number)
    except phonenumbers.NumberParseException as e:
        return {"query": number, "error": str(e)}

    results = {}
    for name in picked:
        fn, key, needs_net = SCANNERS[name]
        if key and not os.environ.get(key):
            results[name] = {"skipped": key + " not set"}
            continue
        try:
            if name == "geo":
                results[name] = scan_geo(local["e164"], "", local["region"])
            else:
                results[name] = cached(local["e164"], name, fn, not args.no_cache)
        except Exception as e:
            results[name] = {"error": "%s: %s" % (type(e).__name__, e)}
        if needs_net and not args.no_cache:
            time.sleep(args.rate)

    return {"query": number, "local": local, "scanners": results}


def main():
    global COLOR
    ap = argparse.ArgumentParser(prog="numtool", description="phone OSINT toolkit v" + VERSION)
    ap.add_argument("number", nargs="?", help="E164 number")
    ap.add_argument("-i", "--input", help="file with one number per line")
    ap.add_argument("-s", "--scanners", default="social,dorks,geo")
    ap.add_argument("-a", "--all", action="store_true", help="all scanners with keys set")
    ap.add_argument("--local-only", action="store_true")
    ap.add_argument("-o", "--out", help="write JSON")
    ap.add_argument("--csv", help="write CSV summary")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--rate", type=float, default=1.0)
    ap.add_argument("-v", "--version", action="version", version=VERSION)
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        COLOR = False

    load_keys()

    if args.local_only:
        picked = []
    elif args.all:
        picked = [n for n, (_, k, _) in SCANNERS.items() if not k or os.environ.get(k)]
    else:
        picked = [s.strip() for s in args.scanners.split(",") if s.strip()]

    bad = [s for s in picked if s not in SCANNERS]
    if bad:
        print(r("unknown scanner: ") + ", ".join(bad))
        return 1

    numbers = []
    if args.input:
        numbers = [l.strip() for l in Path(args.input).read_text().splitlines()
                   if l.strip() and not l.startswith("#")]
    elif args.number:
        numbers = [args.number]
    else:
        ap.error("give a number or -i file")

    all_data = []
    for num in numbers:
        data = run(num, picked, args)
        all_data.append(data)
        if args.json:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        elif args.quiet or len(numbers) > 1:
            one_line(data)
        else:
            render(data)
        if not args.no_cache:
            time.sleep(args.rate)

    if args.out:
        Path(args.out).write_text(json.dumps(all_data, indent=2, ensure_ascii=False))
        print(dim("json -> " + args.out))

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["number", "valid", "country", "region", "carrier", "line_type", "tz"])
            for d in all_data:
                l = d.get("local", {})
                w.writerow([d["query"], l.get("valid"), l.get("country"),
                            l.get("region"), l.get("carrier"), l.get("line_type"),
                            ",".join(l.get("timezones", []))])
        print(dim("csv -> " + args.csv))

    return 0


if __name__ == "__main__":
    sys.exit(main())
