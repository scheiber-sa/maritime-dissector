#!/usr/bin/env python3
import requests
import os
import json
import argparse
from collections import defaultdict

ONLINE = False

UNSUPPORTED = [130817, 130818]

# Argument parsing
parser = argparse.ArgumentParser(
    description="Generate Lua PGN files from canboat.json for NMEA 2000 dissector."
)
parser.add_argument(
    '-p', '--pgn-json-path',
    type=str,
    default='../../docs/canboat.json',
    help='Path to pgn json path (default: ../../docs/canboat.json)'
)
args = parser.parse_args()
json_path = args.pgn_json_path
# Get the directory of this script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Download NMEA2000 definition
if os.path.isfile(json_path):
    print(f"Using {json_path} ...")
    with open(json_path, "r") as f:
        data = json.load(f)
else:
    print("Downloading upstream canboat NMEA2000 definition ...")
    url = "https://raw.githubusercontent.com/canboat/canboat/refs/heads/master/docs/canboat.json"
    response = requests.get(url)
    data = json.loads(response.content)

with open(os.path.join(script_dir, "pgn.lua"), "w") as f:
    f.write(f"""-- prevent wireshark loading this file as plugin
if not _G['maritimedissector'] then return end

-- WARNING: This file is generated automatically by ./pgn.py --

-- List of known PGN for NMEA 2000 (Source: https://github.com/canboat/canboat/blob/master/sources/NMEA_database_1_300.xml)
local known_pgns = {{\n""")

    pgn_descriptions = defaultdict(list)
    for pgn in data["PGNs"]:
        if pgn["PGN"] in UNSUPPORTED:
            continue

        if pgn["Description"] not in pgn_descriptions[pgn["PGN"]]:
            pgn_descriptions[pgn["PGN"]].append(pgn["Description"])

    for pgn, descriptions in pgn_descriptions.items():
        description = descriptions[0] if len(descriptions) == 1 else "Multiple definitions"
        f.write(f"\t[{int(pgn)}]=\"{description}\",\n")

    f.write(f"""}}

return known_pgns""")

with open(os.path.join(script_dir, "pgn-fragmented.lua"), "w") as f:
    f.write(f"""-- prevent wireshark loading this file as plugin
if not _G['maritimedissector'] then return end

-- WARNING: This file is generated automatically by ./pgn.py --

-- List of fragmented PGN for NMEA 2000 (Source: https://github.com/canboat/canboat/blob/master/sources/NMEA_database_1_300.xml)
local fragmented_pgns = {{\n""")

    # Parse XML without repeating values
    fragmented = set()
    for pgn in data["PGNs"]:
        if pgn["PGN"] in UNSUPPORTED:
            continue

        if pgn["Type"] == "Fast":
            if pgn["PGN"] in fragmented:
                continue
            fragmented.add(pgn["PGN"])
            f.write(f"\t[{int(pgn["PGN"])}]=true,\n")

    f.write(f"""}}

return fragmented_pgns""")
