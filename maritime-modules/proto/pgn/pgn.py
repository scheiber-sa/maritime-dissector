#!/usr/bin/env python3
import requests
import json
import os
import argparse
import re

UNSUPPORTED = [130817, 130818]
LUA_KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return",
    "then", "true", "until", "while"
}

# Argument parsing
parser = argparse.ArgumentParser(
    description="Generate NMEA2000 lua PGN dissector files from canboat.json."
)
parser.add_argument(
    '-p', '--pgn-json-path',
    type=str,
    default='../../docs/canboat.json',
    help='Path to pgn json path (default: ../../docs/canboat.json relative to this script)'
)
args = parser.parse_args()
json_path = args.pgn_json_path
# Get the directory of this script
script_dir = os.path.dirname(os.path.abspath(__file__))
# Resolve relative paths with respect to the script location so running from any cwd finds the repo copy.
if not os.path.isabs(json_path):
    json_path = os.path.abspath(os.path.join(script_dir, json_path))

def get_bitmask(length, offset): # Note Litle endian
    mask = 0x00
    while length > 0:
        mask = mask << 1 | 0x01
        length -= 1

    while offset > 0:
        mask = mask << 1
        offset -= 1
    return hex(mask)

def sanitize_lua_identifier(identifier):
    if identifier.startswith("1st"):
        identifier = "first" + identifier[3:]
    identifier = re.sub(r"[^0-9A-Za-z_]", "_", identifier)
    if not identifier:
        identifier = "field"
    if identifier[0].isdigit() or identifier in LUA_KEYWORDS:
        identifier = f"field_{identifier}"
    return identifier

def parse_field(field, pgn_full):
    pgn = pgn_full["PGN"]
    print_format = f"""{pgn:<6} {pgn_full["Id"]:<59} {field["Id"]:<31} {field["FieldType"]:<20}"""
    extra_protos = []
    extra_trees = []
    extra_names = []

    if "FieldType" not in field:
        if not field["Id"].endswith("RepeatAsNeeded") and not field["Id"].endswith("RepeatedAsNeeded"):
            print(f"{print_format} Missing Fieldtype")
        else:
            pass # TODO Handle those types
        return [], [], [], False

    # PGN specific
    if pgn_full["PGN"] == 60928:
        if field["Id"] == "uniqueNumber":
            extra_protos.append(
                'local uniqueNumber_hex = ProtoField.uint32("nmea-2000-60928.uniqueNumber_hex", "Unique Number (HEX)", base.HEX)'
            )
            extra_trees.append(f"""subtree:add(uniqueNumber_hex, rng_{field["Id"]}, v_{field["Id"]})""")
            extra_names.append("uniqueNumber_hex")

    ######### Integer
    if field["FieldType"] in ["NUMBER", "DATE", "TIME", "DURATION", "PGN", "ISO_NAME", "MMSI"]: # uint8 uint16 uint32 int8 ...
        if "BitOffset" not in field or "BitLength" not in field:
            print(f"{print_format} Missing BitOffset or BitLength")
            return [], [], [], False

        bit_offset = int(field["BitOffset"])
        bit_length = int(field["BitLength"])

        # bit-sized (non byte-aligned) integers: use helper to extract arbitrary little-endian bit ranges
        if bit_offset % 8 != 0 or bit_length % 8 != 0:
            scale = field.get("Resolution", 1)
            signed = field.get("Signed", False)

            proto = f"""local {field["Id"]} = ProtoField.double("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}{" ("+field["Unit"]+")" if "Unit" in field else ""}")"""

            tree = f"""local v_{field["Id"]}, rng_{field["Id"]} = read_bits_le(buffer, {bit_offset}, {bit_length})
    {"if v_"+field["Id"]+" >= 2^(" + str(bit_length-1) + ") then v_"+field["Id"]+" = v_"+field["Id"]+" - 2^" + str(bit_length) + " end" if signed else ""}
    subtree:add({field["Id"]}, rng_{field["Id"]}, v_{field["Id"]} * {scale})"""

            return [proto] + extra_protos, [tree] + extra_trees, [field["Id"]] + extra_names, True

        if "BitStart" in field and int(field["BitStart"]) % 8 != 0:
            print(f"{print_format} BitStart not divisible by 8")
            return [], [], [], False

        if bit_length % 8 != 0:
            print(f"{print_format} BitLength not divisible by 8")
            return [], [], [], False

        assert bit_offset % 8 == 0
        assert bit_length % 8 == 0

        if "Resolution" in field:
            scale = field["Resolution"]
            proto = f"""local {field["Id"]} = ProtoField.double("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}{" ("+field["Unit"]+")" if "Unit" in field else ""}")"""

            if "Signed" not in field: # NOTE default unsigned for DATE/TIME/DURATION/PGN/ISO_NAME/MMSI
                field["Signed"] = False

            if field["Signed"]:
                tree = f"""subtree:add({field["Id"]}, buffer(str_offset + {int(field["BitOffset"]) // 8}, {int(field["BitLength"]) // 8}), buffer(str_offset + {int(field["BitOffset"]) // 8}, {int(field["BitLength"]) // 8}):le_int{"64():tonumber" if field["BitLength"] == "64" else ""}() * {scale})"""
            else:
                tree = f"""subtree:add({field["Id"]}, buffer(str_offset + {int(field["BitOffset"]) // 8}, {int(field["BitLength"]) // 8}), buffer(str_offset + {int(field["BitOffset"]) // 8}, {int(field["BitLength"]) // 8}):le_uint{"64():tonumber" if field["BitLength"] == "64" else ""}() * {scale})"""

        else:
            assert False

        return [proto] + extra_protos, [tree] + extra_trees, [field["Id"]] + extra_names, False

    ######### Float
    elif field["FieldType"] == "FLOAT": # float32 resolution 1, signed 1
        assert int(field["BitStart"]) % 8 == 0
        assert int(field["BitOffset"]) % 8 == 0
        assert int(field["BitLength"]) == 32
        assert field["Signed"] == True

        proto = f"""local {field["Id"]} = ProtoField.float("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}{" ("+field["Unit"]+")" if "Unit" in field else ""}")"""

        tree = f"""subtree:add({field["Id"]}, buffer(str_offset + {int(field["BitOffset"]) // 8}, {int(field["BitLength"]) // 8}))"""

        return [proto] + extra_protos, [tree] + extra_trees, [field["Id"]] + extra_names, False

    ######### Bit Lookup
    elif field["FieldType"] == "BITLOOKUP":
        if "BitOffset" not in field:
            print(f"{print_format} Missing BitOffset")
            return [], [], [], False

        if "BitLength" not in field:
            print(f"{print_format} Missing BitLength")
            return [], [], [], False

        bit_offset = int(field["BitOffset"])
        bit_length = int(field["BitLength"])

        if bit_length > 32:
            print(f"{print_format} bit length too long")
            return [], [], [], False

        assert "Resolution" not in field or field["Resolution"] == 1
        assert field.get("Signed", False) == False

        if bit_length <= 8:
            proto_type = "ProtoField.uint8"
        elif bit_length <= 16:
            proto_type = "ProtoField.uint16"
        else:
            proto_type = "ProtoField.uint32"

        proto = f"""local {field["Id"]} = {proto_type}("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}{" ("+field["Unit"]+")" if "Unit" in field else ""}")"""

        tree_lines = [
            f"""local v_{field["Id"]}, rng_{field["Id"]} = read_bits_le(buffer, {bit_offset}, {bit_length})""",
            f"""    local {field["Id"]}_tree = subtree:add({field["Id"]}, rng_{field["Id"]}, v_{field["Id"]})"""
        ]

        bit_proto_lines = []
        bit_field_names = []
        bit_tree_lines = []

        lookup_name = field.get("LookupBitEnumeration")
        if lookup_name:
            bit_enum = LOOKUP_BIT_ENUMS.get(lookup_name)
            if bit_enum:
                for entry in sorted(bit_enum.get("EnumBitValues", []), key=lambda e: int(e.get("Bit", 0))):
                    if "Bit" not in entry:
                        continue
                    try:
                        bit_num = int(entry["Bit"])
                    except (ValueError, TypeError):
                        continue
                    bit_label = entry.get("Name", f"Bit {bit_num}")
                    bit_label = bit_label.replace("\\", "\\\\").replace("\"", "\\\"")
                    bit_var = f"""{field["Id"]}_bit_{bit_num}"""
                    bit_proto_lines.append(
                        f"""local {bit_var} = ProtoField.bool("nmea-2000-{pgn}.{field["Id"]}.bit_{bit_num}", "{bit_label}", base.NONE)"""
                    )
                    bit_tree_lines.append(
                        f"""    {field["Id"]}_tree:add({bit_var}, rng_{field["Id"]}, math.floor(v_{field["Id"]} / 2^{bit_num}) % 2 == 1)"""
                    )
                    bit_field_names.append(bit_var)
            else:
                print(f"{print_format} LookupBitEnumeration {lookup_name} not found")

        tree_lines.extend(bit_tree_lines)
        tree = "\n".join(tree_lines)

        return [proto] + bit_proto_lines + extra_protos, [tree] + extra_trees, [field["Id"]] + bit_field_names + extra_names, True

    ######### Other Lookup
    elif field["FieldType"] in ["LOOKUP", "INDIRECT_LOOKUP", "FIELDTYPE_LOOKUP"]:
        if "BitOffset" not in field:
            print(f"{print_format} Missing BitOffset")
            return [], [], [], False

        if "BitLength" not in field:
            if pgn not in ["129792", "129795", "129797"]:
                print(f"{print_format} Missing BitLength")
            else:
                pass # TODO handle these fields
            return [], [], [], False

        bit_offset = int(field["BitOffset"])
        bit_length = int(field["BitLength"])
        bit_start = int(field.get("BitStart", 0))

        if bit_length > 32:
            print(f"{print_format} bit length too long")
            return [], [], [], False

        assert "Resolution" not in field or field["Resolution"] == 1
        assert field.get("Signed", False) == False

        simple_mask = bit_length <= 8 and bit_offset % 8 == 0 and (bit_offset - bit_start) % 8 == 0
        proto_type = "ProtoField.uint8" if simple_mask else "ProtoField.uint32"
        proto = f"""local {field["Id"]} = {proto_type}("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}{" ("+field["Unit"]+")" if "Unit" in field else ""}")"""

        tree_lines = [
            f"""local v_{field["Id"]}, rng_{field["Id"]} = read_bits_le(buffer, {bit_offset}, {bit_length})""",
            f"""    local {field["Id"]}_tree = subtree:add({field["Id"]}, rng_{field["Id"]}, v_{field["Id"]})"""
        ]

        def build_lookup_entries(enumerator, key_names):
            entries = []
            for entry in enumerator.get(key_names, []):
                entry_value = None
                for key in ("value", "Value"):
                    if key in entry:
                        entry_value = entry[key]
                        break
                if entry_value is None:
                    continue
                try:
                    entry_value = int(entry_value)
                except (ValueError, TypeError):
                    continue
                entry_label = entry.get("name") or entry.get("Name") or f"Value {entry_value}"
                entry_label = entry_label.replace("\\", "\\\\").replace("\"", "\\\"")
                entries.append((entry_value, entry_label))
            return entries

        lookup_proto_lines = []
        lookup_entries = []
        enum_key = None
        lookup_name = None
        lookup_table = LOOKUP_ENUMS
        field_type = field["FieldType"]
        reference_field = None
        reference_bit_offset = None
        reference_bit_length = None
        reference_var = None
        if field_type == "FIELDTYPE_LOOKUP":
            lookup_name = field.get("LookupFieldTypeEnumeration")
            search_table = LOOKUP_FIELD_TYPE_ENUMS
            enum_key = "EnumFieldTypeValues"
        elif field_type == "INDIRECT_LOOKUP":
            lookup_name = field.get("LookupIndirectEnumeration")
            search_table = LOOKUP_INDIRECT_ENUMS
            enum_key = "EnumValues"
            reference_order = field.get("LookupIndirectEnumerationFieldOrder")
            if reference_order is not None:
                try:
                    reference_order = int(reference_order)
                except (TypeError, ValueError):
                    reference_order = None
            if reference_order is not None:
                ref_candidate = next((f for f in pgn_full["Fields"] if int(f.get("Order", -1)) == reference_order), None)
                if ref_candidate and "BitOffset" in ref_candidate and "BitLength" in ref_candidate:
                    reference_field = ref_candidate
                    reference_bit_offset = int(ref_candidate["BitOffset"])
                    reference_bit_length = int(ref_candidate["BitLength"])
                    reference_var = ref_candidate["Id"]
        else:
            lookup_name = field.get("LookupEnumeration")
            search_table = LOOKUP_ENUMS
            enum_key = "EnumValues"

        if lookup_name:
            lookup_enumerator = search_table.get(lookup_name)
            if lookup_enumerator:
                if field_type == "INDIRECT_LOOKUP":
                    lookup_entries = []
                    for entry in lookup_enumerator.get("EnumValues", []):
                        value1 = entry.get("Value1")
                        value2 = entry.get("Value2")
                        if value1 is None or value2 is None:
                            continue
                        try:
                            value1 = int(value1)
                            value2 = int(value2)
                        except (TypeError, ValueError):
                            continue
                        label = entry.get("Name", f"Value {value1}/{value2}")
                        label = label.replace("\\", "\\\\").replace("\"", "\\\"")
                        lookup_entries.append((value1, value2, label))
                else:
                    lookup_entries = build_lookup_entries(lookup_enumerator, enum_key)
                    lookup_entries.sort(key=lambda x: x[0])
                if lookup_entries:
                    lookup_table = f"""{field["Id"]}_lookup"""
                    if field_type == "INDIRECT_LOOKUP":
                        lookup_proto_lines.append(
                            f"""local {lookup_table} = {{{", ".join(f"[\"{v1},{v2}\"] = \"{lbl}\"" for v1, v2, lbl in lookup_entries)}}}"""
                        )
                    else:
                        lookup_proto_lines.append(
                            f"""local {lookup_table} = {{{", ".join(f"[{val}] = \"{lbl}\"" for val, lbl in lookup_entries)}}}"""
                        )
                    if field_type == "INDIRECT_LOOKUP":
                        if reference_field:
                            tree_lines.append(f"""    local v_{reference_var}, rng_{reference_var} = read_bits_le(buffer, {reference_bit_offset}, {reference_bit_length})""")
                            tree_lines.append(f"""    local lookup_key = tostring(v_{reference_var}) .. "," .. tostring(v_{field["Id"]})""")
                        else:
                            tree_lines.append(f"""    local lookup_key = tostring(v_{field["Id"]})""")
                        tree_lines.append(f"""    local lookup_label = {lookup_table}[lookup_key]""")
                    else:
                        tree_lines.append(f"""    local lookup_label = {lookup_table}[v_{field["Id"]}]""")
                    tree_lines.append(f"""    if lookup_label then {field["Id"]}_tree:append_text(" (" .. lookup_label .. ")") end""")
            else:
                descriptor_name = {
                    "FIELDTYPE_LOOKUP": "LookupFieldTypeEnumeration",
                    "INDIRECT_LOOKUP": "LookupIndirectEnumeration",
                }.get(field_type, "LookupEnumeration")
                print(f"{print_format} {descriptor_name} {lookup_name} not found")

        tree = "\n".join(tree_lines)

        return [proto] + lookup_proto_lines + extra_protos, [tree] + extra_trees, [field["Id"]] + extra_names, True

    ######### Binary
    elif field["FieldType"] == "BINARY":
        if "BitOffset" not in field:
            print(f"{print_format} Missing BitOffset")
            return [], [], [], False

        bit_offset = int(field["BitOffset"])
        bit_length = field.get("BitLength")
        bit_length_variable = field.get("BitLengthVariable", False)

        if bit_length_variable:
            if "BitLengthField" not in field:
                print(f"{print_format} Missing BitLengthField")
                return [], [], [], False

            referenced_order = int(field["BitLengthField"])
            length_field = next((f for f in pgn_full["Fields"] if int(f.get("Order", -1)) == referenced_order), None)
            if not length_field or "BitOffset" not in length_field or "BitLength" not in length_field:
                print(f"{print_format} Missing referenced field for variable BINARY length")
                return [], [], [], False

            length_bit_offset = int(length_field["BitOffset"])
            length_bit_length = int(length_field["BitLength"])
            byte_offset = bit_offset // 8

            proto = f"""local {field["Id"]} = ProtoField.bytes("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}")"""

            tree = f"""local v_bits_{field["Id"]} = read_bits_le(buffer, {length_bit_offset}, {length_bit_length})
    local start_{field["Id"]} = str_offset + {byte_offset}
    local byte_len_{field["Id"]} = math.ceil(v_bits_{field["Id"]} / 8)
    local available_{field["Id"]} = math.max(buffer:len() - start_{field["Id"]}, 0)
    byte_len_{field["Id"]} = math.min(byte_len_{field["Id"]}, available_{field["Id"]})
    subtree:add({field["Id"]}, buffer(start_{field["Id"]}, byte_len_{field["Id"]}))
    str_offset = start_{field["Id"]} + byte_len_{field["Id"]}"""
            return [proto], [tree], [field["Id"]], True

        if bit_length is None:
            print(f"{print_format} Missing BitLength")
            return [], [], [], False

        bit_length = int(bit_length)
        has_following = any(int(f.get("Order", 0)) > int(field.get("Order", 0)) for f in pgn_full.get("Fields", []))

        if bit_length <= 64 and has_following:
            if bit_length <= 8:
                proto_type = "ProtoField.uint8"
            elif bit_length <= 16:
                proto_type = "ProtoField.uint16"
            elif bit_length <= 32:
                proto_type = "ProtoField.uint32"
            else:
                proto_type = "ProtoField.uint64"

            proto = f"""local {field["Id"]} = {proto_type}("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}", base.HEX)"""
            tree = f"""local v_{field["Id"]}, rng_{field["Id"]} = read_bits_le(buffer, {bit_offset}, {bit_length})
    subtree:add({field["Id"]}, rng_{field["Id"]}, v_{field["Id"]})"""
            return [proto] + extra_protos, [tree] + extra_trees, [field["Id"]] + extra_names, True

        if bit_offset % 8 != 0:
            print(f"{print_format} BitOffset not divisible by 8")
            return [], [], [], False

        byte_len = (bit_length + 7) // 8
        byte_offset = bit_offset // 8
        proto = f"""local {field["Id"]} = ProtoField.bytes("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}")"""
        tree = f"""subtree:add({field["Id"]}, buffer(str_offset + {byte_offset}, {byte_len}))"""

        return [proto] + extra_protos, [tree] + extra_trees, [field["Id"]] + extra_names, False

    ######### String FIX
    elif field["FieldType"] == "STRING_FIX":
        if "BitOffset" not in field or "BitLength" not in field:
            print(f"{print_format} Missing BitOffset or BitLength")
            return [], [], [], False

        assert "BitStart" not in field or int(field["BitStart"]) == 0
        assert int(field["BitOffset"]) % 8 == 0
        assert int(field["BitLength"]) % 8 == 0

        proto = f"""local {field["Id"]} = ProtoField.string("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}{" ("+field["Unit"]+")" if "Unit" in field else ""}")"""

        tree = f"""subtree:add({field["Id"]}, buffer(str_offset + {int(field["BitOffset"]) // 8}, {int(field["BitLength"]) // 8}))"""

        return [proto] + extra_protos, [tree] + extra_trees, [field["Id"]] + extra_names, False

    ######### Decimal BCD
    elif field["FieldType"] == "DECIMAL":
        if "BitOffset" not in field or "BitLength" not in field:
            print(f"{print_format} Missing BitOffset or BitLength")
            return [], [], [], False

        bit_offset = int(field["BitOffset"])
        bit_length = int(field["BitLength"])

        if bit_length % 8 != 0:
            print(f"{print_format} BitLength not divisible by 8")
            return [], [], [], False

        byte_offset = bit_offset // 8
        byte_len = bit_length // 8

        proto = f"""local {field["Id"]} = ProtoField.string("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}")"""

        tree = f"""local raw_{field["Id"]} = buffer(str_offset + {byte_offset}, {byte_len})
    local digits_{field["Id"]} = {{}}
    for i=0,{byte_len - 1} do
        local byte_{field["Id"]} = raw_{field["Id"]}(i,1):uint()
        local hi_{field["Id"]} = math.floor(byte_{field["Id"]} / 16)
        local lo_{field["Id"]} = byte_{field["Id"]} % 16
        digits_{field["Id"]}[#digits_{field["Id"]} + 1] = tostring(hi_{field["Id"]})
        digits_{field["Id"]}[#digits_{field["Id"]} + 1] = tostring(lo_{field["Id"]})
    end
    local decimal_{field["Id"]} = table.concat(digits_{field["Id"]})
    subtree:add({field["Id"]}, raw_{field["Id"]}):append_text(" (" .. decimal_{field["Id"]} .. ")")"""

        return [proto] + extra_protos, [tree] + extra_trees, [field["Id"]] + extra_names, False

    ######### String LAU
    elif field["FieldType"] in ["STRING_LAU", "STRING_LZ"]:
        # Variable encoding 1. byte length 2. byte type (0 UNICODE, 1 ASCII)
        # TODO Problem: other fields after a STRING_LAU may change their position depending on the length of the string

        if "BitOffset" not in field:
            field["BitOffset"] = 0 # Hack: we rely on str_offset

        assert "BitStart" not in field or int(field["BitStart"]) == 0
        assert int(field["BitOffset"]) % 8 == 0

        proto = f"""local {field["Id"]} = ProtoField.string("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}{" ("+field["Unit"]+")" if "Unit" in field else ""}")"""
        byte_offset = int(field["BitOffset"]) // 8

        if field["FieldType"] == "STRING_LAU":
             tree = f"""local start_length = str_offset + {byte_offset}
    local length = 0
    if buffer:len() > start_length then
        length = math.max(buffer(start_length, 1):uint() - 2, 0)
    end
    local start = start_length + 2
    local available = math.max(buffer:len() - start, 0)
    local actual_len = math.min(length, available)
    local payload_buf
    if start < buffer:len() then
        payload_buf = buffer(start, actual_len)
    else
        payload_buf = buffer(buffer:len(), 0)
    end
    subtree:add({field["Id"]}, payload_buf)
    str_offset = start_length + 2 + actual_len"""

        elif field["FieldType"] == "STRING_LZ":
            tree = f"""local length_{field["Id"]} = buffer(str_offset + {byte_offset}, 1):uint()
    local payload_start_{field["Id"]} = str_offset + {byte_offset} + 1
    local available_{field["Id"]} = math.max(buffer:len() - payload_start_{field["Id"]}, 0)
    local string_len_{field["Id"]} = math.min(length_{field["Id"]}, math.max(available_{field["Id"]} - 1, 0))
    subtree:add({field["Id"]}, buffer(payload_start_{field["Id"]}, string_len_{field["Id"]}))
    str_offset = str_offset + length_{field["Id"]} + 2"""

        return [proto] + extra_protos, [tree] + extra_trees, [field["Id"]] + extra_names, False

    ######### Unknown
    elif field["FieldType"] in ["SPARE", "RESERVED"]:
        if "BitOffset" not in field or "BitLength" not in field:
            print(f"{print_format} Missing BitOffset or BitLength")
            return [], [], [], False

        bit_offset = int(field["BitOffset"])
        bit_length = int(field["BitLength"])
        bit_start = int(field.get("BitStart", 0))

        if bit_length > 32:
            print(f"{print_format} spare/reserved too long")
            return [], [], [], False

        if bit_length <= 8 and bit_offset % 8 == 0 and (bit_offset - bit_start) % 8 == 0:
            proto = f"""local {field["Id"]} = ProtoField.uint8("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}")"""
            tree = f"""subtree:add({field["Id"]}, buffer(str_offset + {bit_offset // 8}, 1))"""
            return [proto], [tree], [field["Id"]], False

        proto = f"""local {field["Id"]} = ProtoField.uint32("nmea-2000-{pgn}.{field["Id"]}", "{field["Name"]}")"""
        tree = f"""local v_{field["Id"]}, rng_{field["Id"]} = read_bits_le(buffer, {bit_offset}, {bit_length})
    subtree:add({field["Id"]}, rng_{field["Id"]}, v_{field["Id"]})"""

        return [proto] + extra_protos, [tree] + extra_trees, [field["Id"]] + extra_names, True

    else: # Unknown
        print(f"{print_format} Unsupported field type")
        return [], [], [], False

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

LOOKUP_BIT_ENUMS = {
    entry["Name"]: entry
    for entry in data.get("LookupBitEnumerations", [])
    if "Name" in entry
}
LOOKUP_ENUMS = {
    entry["Name"]: entry
    for entry in data.get("LookupEnumerations", [])
    if "Name" in entry
}
LOOKUP_INDIRECT_ENUMS = {
    entry["Name"]: entry
    for entry in data.get("LookupIndirectEnumerations", [])
    if "Name" in entry
}
LOOKUP_FIELD_TYPE_ENUMS = {
    entry["Name"]: entry
    for entry in data.get("LookupFieldTypeEnumerations", [])
    if "Name" in entry
}

# Parse NMEA2000 definition
created = []
print(f"""PGN{"":<3} PGN_Id{"":<53} FieldId{"":<24} FieldType{"":<11} Error""")
for pgn in data["PGNs"]:

    if pgn["PGN"] in UNSUPPORTED:
        print(f"{pgn["PGN"]:<6} {"":<112} Unsupported PGN""")
        # print(json.dumps(field, indent=4), pgn)
        continue

    created.append(pgn["PGN"])
    fieldnames = []
    proto_fields = []
    tree_nodes = []
    need_bit_helper = False

    used_field_ids = set()
    for field in pgn["Fields"]:
        base_id = sanitize_lua_identifier(field["Id"])
        field_id = base_id
        suffix = 2
        while field_id in used_field_ids:
            field_id = f"{base_id}_{suffix}"
            suffix += 1
        field["Id"] = field_id
        used_field_ids.add(field_id)

    for field in pgn["Fields"]:
        proto, tree, name, helper = parse_field(field, pgn)
        proto_fields += proto
        tree_nodes += tree
        fieldnames += name
        need_bit_helper = need_bit_helper or helper

    if pgn["PGN"] == 60928:
        iso_name_proto = 'local isoName = ProtoField.uint64("nmea-2000-60928.isoName", "isoName", base.HEX)'
        iso_name_tree = """local isoName_range = buffer(str_offset, 8)
    subtree:add(isoName, isoName_range, isoName_range:le_uint64())"""
        proto_fields.insert(0, iso_name_proto)
        tree_nodes.insert(0, iso_name_tree)
        fieldnames.insert(0, "isoName")

    # Write pgn_***.lua files
    with open(os.path.join(script_dir, f"pgn_{pgn['PGN']}.lua"), "w") as f:

        f.write(f"""-- prevent wireshark loading this file as plugin
if not _G['maritimedissector'] then return end

-- WARNING: This file is generated automatically by ./pgn.py --

NMEA_2000_{pgn["PGN"]} = Proto("nmea-2000-{pgn["PGN"]}", "{pgn["Description"]} ({pgn["PGN"]})")\n""")

        for field in proto_fields:
            f.write(f"""{field}\n""")

        if need_bit_helper:
            f.write("""
local function read_bits_le(buf, bit_offset, bit_length)
    local byte_offset = math.floor(bit_offset / 8)
    local bit_in_byte = bit_offset % 8
    local needed_bits = bit_in_byte + bit_length
    local byte_len = math.ceil(needed_bits / 8)
    local raw
    if byte_len <= 4 then
        raw = buf(byte_offset, byte_len):le_uint()
    else
        raw = buf(byte_offset, byte_len):le_uint64():tonumber()
    end
    return math.floor(raw / 2^bit_in_byte) % 2^bit_length, buf(byte_offset, byte_len)
end
""")

        f.write(f"""\nNMEA_2000_{pgn["PGN"]}.fields = {{{",".join(fieldnames)}}}

function NMEA_2000_{pgn["PGN"]}.dissector(buffer, pinfo, tree)
    local subtree_title = "PGN {pgn["PGN"]} ({pgn["Description"]})"
    local subtree = tree:add(NMEA_2000_{pgn["PGN"]}, buffer(), subtree_title)
    local str_offset = 0\n\n""")

        for node in tree_nodes:
            f.write(f"""    {node}\n""")

        f.write(f"""end

return NMEA_2000_{pgn["PGN"]}
""")

with open(os.path.join(script_dir, "pgn.lua"), "w") as f:
    f.write(f"""-- prevent wireshark loading this file as plugin
if not _G['maritimedissector'] then return end

-- WARNING: This file is generated automatically by ./pgn.py --

local pgn_dissector = {{}}

""")

    # Deduplicate PGNs while preserving order (some PGNs have multiple definitions)
    unique_created = []
    seen = set()
    for c in created:
        if c not in seen:
            unique_created.append(c)
            seen.add(c)

    for c in unique_created:
        f.write(f"NMEA_2000_{c} = require \"maritime-modules.proto.pgn.pgn_{c}\"\n")

    f.write(f"""\nfunction pgn_dissector.dissector(buffer, pinfo, tree, pgn)\n""")

    for idx, c in enumerate(unique_created):
        f.write(f"""    {"if" if idx == 0 else "elseif"} pgn == {c} then
        NMEA_2000_{c}.dissector(buffer, pinfo, tree)\n""")

    f.write(f"""    else
        return false
    end

    return true
end

return pgn_dissector""")
