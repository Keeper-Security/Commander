#!/usr/bin/env python3
"""
Generates JSON file ready to be imported by pam project import command.
This example generates JSON that creates one AD machine (pamDirectory)
with AD Admin user (pamUser) and multiple local machines (pamMachine)
configured with connections and rotation enabled and AD Admin as their admin.

This script uses external CSV file (format: server_name,user_name,password)
and external JSON template with static pamDirectory and its pamUser and
a dynamic placeholder used for each pamMachine and its pamUser (from CSV)

You can use any of the full set of options per user/machine type from our docs
https://github.com/Keeper-Security/Commander/blob/master/keepercommander/commands/pam_import/README.md
You can also run the script with --show-template option and use it as startnig point.

Command line options:
    -i, --input-file    default = servers_to_import.csv
                        Specify the input file CSV: hostname,user,password
    -o, --output-file   default = pam_import.json
                        Specify the JSON output file
    -t, --template-file default = import_template.json
                        Specify the JSON template file
    -s, --show-template Show sample JSON template (overrides all options)
    -p, --prefix-names  Enable username prefixes (server1-admin vs admin)
"""
from __future__ import annotations

import argparse
import copy
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_IMPORT_TEMPLATE = """{
    "project": "Project1",
    "shared_folder_users": { "manage_users": true, "manage_records": true, "can_edit": true, "can_share": true },
    "shared_folder_resources": { "manage_users": true, "manage_records": true, "can_edit": true, "can_share": true },
    "pam_configuration": { "environment": "local", "connections": "on", "rotation": "on", "graphical_session_recording": "on" },
    "pam_data": {
        "resources": [
            {
                "_comment1": "Every key that starts with '_' is a comment and can be ignored or deleted",
                "_comment2": "Every value that starts with uppercase 'XXX:' must be replaced with actual value (removed if not required)",
                "_comment3": "Every value that starts with lowercase 'xxx:' is just a placeholder - can be replaced with anything but must be present",
                "type": "pamDirectory",
                "title": "XXX:Project1 AD",
                "directory_type": "XXX:active_directory|ldap",
                "host": "XXX:demo.local",
                "port": "XXX:636",
                "use_ssl": true,
                "domain_name": "XXX:demo.local",
                "pam_settings": {
                    "options" : { "rotation": "on", "connections": "on", "tunneling": "on", "graphical_session_recording": "on" },
                    "connection" : {
                        "protocol": "rdp",
                        "port": "XXX:3389",
                        "security": "XXX:any",
                        "ignore_server_cert": true,
                        "_comment_administrative_credentials": "Must match the unique title of one of the users below",
                        "administrative_credentials": "XXX:DomainAdmin"
                    }
                },
                "users": [{
                    "type": "pamUser",
                    "_comment_title": "Must match administrative_credentials above if this is the admin user",
                    "title": "XXX:DomainAdmin",
                    "_comment_login_password": "Must provide valid credentials but delete sensitive data/json after import",
                    "login": "XXX:administrator@demo.local",
                    "password": "XXX:P4ssw0rd_123",
                    "rotation_settings": { "rotation": "general", "enabled": "on", "schedule": {"type": "on-demand"}}
                }]
            },
            {
                "_comment4": "While pamDirectory section above is static, the pamMachine section below is dynamically generated",
                "_comment5": "One pamMachine with one pamUser will be generated per each line from the CSV file",
                "_comment6": "Only one pamMachine is needed and it will be used as a template for all CSV rows",
                "_comment7": "Please do NOT edit lines with xxx: in them - these are placeholders",
                "_comment8": "Any other line that don't contain xxx: can be altered/added/deleted in the template",
                "_comment9": "CSV Format: server_name,username,password",
                "type": "pamMachine",
                "_comment_title_and_host": "server value from CSV",
                "title": "xxx:server1",
                "host": "xxx:server1",
                "port": "5986",
                "ssl_verification" : true,
                "operating_system": "Windows",
                "pam_settings": {
                    "options" : { "rotation": "on", "connections": "on", "tunneling": "on", "graphical_session_recording": "on" },
                    "connection" : {
                        "protocol": "rdp",
                        "port": "3389",
                        "security": "any",
                        "ignore_server_cert": true,
                        "_comment_administrative_credentials": "Format: pamDirectory#title.pamDirectory#administrative_credentials - exact match needed",
                        "administrative_credentials": "XXX:Project1 AD.DomainAdmin"
                    }
                },
                "users": [{
                    "type": "pamUser",
                    "_comment_title": "username value from CSV or server-username if --prefix-names option is used",
                    "title": "xxx:admin",
                    "_comment_login": "username value from CSV",
                    "login": "xxx:Administrator",
                    "_comment_password": "password value from CSV",
                    "password": "xxx:P4ssw0rd_123",
                    "rotation_settings": { "rotation": "general", "enabled": "on", "schedule": {"type": "on-demand"} }
                }]
            }
        ]
    }
}"""


def _build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generate Keeper PAM import JSON file",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    p.add_argument("-i", "--input-file", default="servers_to_import.csv",
                   help="Specify the input file - "
                   "CSV with hostname,user,password (default: %(default)s)")
    p.add_argument("-o", "--output-file", default="pam_import.json",
                   help="Specify the JSON output file (default: %(default)s)")
    p.add_argument("-t", "--template-file", default="import_template.json",
                   help="Specify the JSON template file (default: %(default)s)")
    p.add_argument("-s", "--show-template", action="store_true",
                   help="Show sample JSON template (overrides all options)")
    p.add_argument("-p", "--prefix-names", action="store_true",
                   help="Enable username prefixes (server1-admin vs admin)")
    return p


def _load_template(path: str) -> Dict[str, Any]:
    full_path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(full_path):
        print(f"JSON template file not found: {path}")
        print("Use --show-template option to get a sample template")
        sys.exit(1)

    res = {}
    with open(full_path, encoding="utf-8") as fp:
        res = json.load(fp)
    return res


def _read_csv(path: str) -> List[Dict[str, str]]:
    full_path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(full_path):
        print(f"CSV file not found: {path}", )
        sys.exit(2)
    fieldnames = ["hostname", "username", "password"]
    out: List[Dict[str, str]] = []
    with open(full_path, encoding="utf-8") as fp:
        reader = csv.DictReader(fp, fieldnames=fieldnames)
        header_row = next(reader)  # skip header row if present
        if list(header_row.values()) != fieldnames:
            fp.seek(0)
            reader = csv.DictReader(fp, fieldnames=fieldnames)
        for line_no, row in enumerate(reader, 0):
            h, u, p = (row.get("hostname", "").strip(),
                       row.get("username", "").strip(),
                       row.get("password", "").strip())
            if not all((h, u, p)):
                print(f"Row {line_no} incomplete - skipped")
                continue
            out.append({"hostname": h, "username": u, "password": p})
    return out


def _gen_data(csv_data: List[Dict[str, str]],
              template: Dict[str, Any],
              prefix_names: bool) -> Dict[str, Any]:

    data = copy.deepcopy(template)

    # pop out pamMachine template
    rsrs = data.get("pam_data", {}).get("resources") or []
    idx = next((i for i, item in enumerate(rsrs) if str(item.get("type")) == "pamMachine"), None)
    tmpl = rsrs.pop(idx) if idx is not None else {}
    if not tmpl:
        print("Unable to find pamMachine template")
        sys.exit(5)

    seen: set[str] = set()
    for row in csv_data:
        mach = copy.deepcopy(tmpl)
        user = row["username"]
        password = row["password"]
        host = row["hostname"]

        if host in seen:
            print(f"Duplicate hostname {host} - skipped")
            continue
        seen.add(host)

        # pamMachine
        mach["title"] = host
        mach["host"] = host
        if "options" not in mach["pam_settings"]:
            mach["pam_settings"]["options"] = {
                "rotation": "on",
                "connections": "on",
                "tunneling": "on",
                "graphical_session_recording": "on"
            }

        # pamUser
        users = mach.get("users") or []
        for usr in users:
            if "type" not in usr:
                usr["type"] = "pamUser"
            usr["title"] = f"{host}-{user}" if prefix_names else host
            usr["login"] = user
            usr["password"] = password
            if "rotation_settings" not in usr:
                usr["rotation_settings"] = {
                    "rotation": "general",
                    "enabled": "on",
                    "schedule": {"type": "on-demand"}
                }
        mach["users"] = users
        rsrs.append(mach)

    data["pam_data"]["resources"] = rsrs
    return data


def _write(fpath: Path, content: str):
    with fpath.open("w", encoding="utf-8") as fp:
        fp.write(content)
    print(f"Wrote {fpath}")


def write_import_json(data: Dict[str, Any], path: str):
    """ Generate JSON and save to file"""
    content = json.dumps(data, indent=2)
    _write(Path(path), content)


def prepare_temlpate(template: Dict[str, Any]) -> None:
    """ Prepare JSON template - populate missing defaults """
    tdic = json.loads(DEFAULT_IMPORT_TEMPLATE)
    if "project" not in template:
        template["project"] = tdic["project"]
    if "shared_folder_users" not in template:
        template["shared_folder_users"] = tdic["shared_folder_users"]
    if "shared_folder_resources" not in template:
        template["shared_folder_resources"] = tdic["shared_folder_resources"]
    if "pam_configuration" not in template:
        template["pam_configuration"] = tdic["pam_configuration"]
    env = str(template["pam_configuration"].get("environment"))
    if env != "local":
        print(f"This script works only with pam_configuration.environment = local, currently it is set to '{env}'")
        sys.exit(4)
    if (str(template["pam_configuration"].get("connections")).lower() != "on" or
            str(template["pam_configuration"].get("rotation")).lower() != "on"):
        print("connections and rotation must be set to 'on' in pam_configuration section - adjusted")
        template["pam_configuration"]["connections"] = "on"
        template["pam_configuration"]["rotation"] = "on"
    if "pam_data" not in template or not template["pam_data"].get("resources"):
        print('"pam_data": { "resources": [] } - must be present and non-empty')
        sys.exit(4)
    res = template["pam_data"].get("resources") or []
    if len(res) != 2:
        print('pam_data.resources[] - must define exactly two "machines": pamDirectory and pamUser')
        sys.exit(4)
    for i in (0, 1):
        mach_type = res[i].get("type") or ""
        mach_usrs = res[i].get("users") or []
        if ((i == 0 and mach_type != "pamDirectory") or (i == 1 and mach_type != "pamMachine") or not mach_usrs):
            print('Expected first machine type=pamDirectory and second type=pamUser, and each to have at least one pamUser')
            sys.exit(4)
        if "pam_settings" not in res[i]:
            print("Missing pam_settings section in pamDirectory or pamMachine")
            sys.exit(4)
        if ("connection" not in res[i]["pam_settings"] or
                "administrative_credentials" not in res[i]["pam_settings"]["connection"]):
            print("Missing pam_settings.connection.administrative_credentials in pamDirectory or pamMachine")
            sys.exit(4)
    # ToDo: verify admin users setup and cross references
    contents = json.dumps(template, indent=2)
    pos = contents.find('"XXX:')
    if pos != -1:
        print(f"Template still missing required values: {contents[pos:pos+80]}")
        sys.exit(4)


def main():
    """ Main function """
    args = _build_cli().parse_args()

    # --show-template overides any other options
    if args.show_template:
        print(DEFAULT_IMPORT_TEMPLATE)
        sys.exit(0)

    rows = _read_csv(args.input_file)
    tmpl = _load_template(args.template_file)
    prepare_temlpate(tmpl)
    print(f"Processing {len(rows)} servers")

    data = _gen_data(rows, tmpl, args.prefix_names)
    write_import_json(data, args.output_file)
    print(f"Import with `pam project import -f={args.output_file}")


if __name__ == "__main__":
    main()
