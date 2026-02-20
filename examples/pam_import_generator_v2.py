#!/usr/bin/env python3
"""
Generates JSON file ready to be imported by pam project import command.
This example generates JSON that creates one AD machine (pamDirectory)
with AD Admin user (pamUser) and multiple local machines (pamMachine)
configured with connections and rotation enabled and AD Admin as their admin.

This script uses external CSV file (format: server_name,user_name,password)
and optionally an external JSON template with static pamDirectory and its pamUser and
a dynamic placeholder used for each pamMachine and its pamUser (from CSV)

You can use any of the full set of options per user/machine type from our docs
https://github.com/Keeper-Security/Commander/blob/master/keepercommander/commands/pam_import/README.md
You can also run the script with --show-template option and use it as startnig point.

Command line options:
    -i, --input-file    default = servers_to_import.csv
                        Specify the input file CSV: hostname,user,password
    -o, --output-file   default = pam_import.json
                        Specify the JSON output file
    -t, --template-file Specify the JSON template file
    -s, --show-template Show sample JSON template (overrides all options)
    -p, --prefix-names  Enable username prefixes (server1-admin vs admin)
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from csv import DictReader
from pathlib import Path
from typing import Any, Dict, List

from time import time

DEFAULT_IMPORT_TEMPLATE = {
  "project": "PAM Project",
  "shared_folder_users": {
    "manage_users": True,
    "manage_records": True,
    "can_edit": True,
    "can_share": True
  },
  "shared_folder_resources": {
    "manage_users": True,
    "manage_records": True,
    "can_edit": True,
    "can_share": True
  },
  "pam_configuration": {
    "environment": "local",
    "connections": "on",
    "rotation": "on",
    "graphical_session_recording": "on"
  },
  "pam_data": {
    "resources": []
  }
}


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
    p.add_argument("-t", "--template-file",
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
        
    with open(full_path, encoding="utf-8") as fp:
        csv_data = list(DictReader(fp))
        # skip incomplete
        valid_rows = []
        for i,obj in enumerate(csv_data):
            host = obj.get('hostname',None)
            username = obj.get('username',None)
            user_path = obj.get('user_path',None)
            if not host and not all([username,user_path]):
                print(f"Row {i+1} incomplete - skipped")
            else:
                valid_rows.append(obj)

    return  valid_rows


def _parse_fields(obj: Dict, type: str):
    templates = {
        'rs':{
            "title": obj.get('title',obj['hostname']),
            "type": obj.get("type","pamMachine"),
            "host": obj['hostname'],
            "pam_settings": {
              "options": {
                "rotation": "off",
                "connections": "on",
                "tunneling": "off",
                "graphical_session_recording": "on"
              },
              "connection":{}
            },
            "users": []
        },
        'usr':{
            "title": obj.get('title',f"{obj['user_path']} - {obj['username']}"),
            "type": "pamUser",
            "login": obj['username'],
            "password": obj.get('password',""),
			"rotation_settings": {}
          }
    }
    res = templates.get(type,{})
    for key in obj:
        if obj[key] == '': continue
        if key.startswith(type):
            split_arg = key.split('.')
            if len(split_arg)==2:
                res[split_arg[1]] = obj[key]
            elif len(split_arg)==3:
                res[split_arg[1]][split_arg[2]] = obj[key]
            elif len(split_arg)==4:
                res[split_arg[1]][split_arg[2]][split_arg[3]] = obj[key]
    return res
            


def _gen_data(csv_data: List[Dict[str, str]],
              template: Dict[str, Any],
              prefix_names: bool) -> Dict[str, Any]:

    data = copy.deepcopy(template) if template else DEFAULT_IMPORT_TEMPLATE

    # pop out pamMachine template
    rsrs = data.get("pam_data", {}).get("resources") or []
    idx = next((i for i, item in enumerate(rsrs) if str(item.get("type")) == "pamMachine"), None)
    tmpl = rsrs.pop(idx) if idx is not None else {}
    

    seen: set[str] = set()
    for i,obj in enumerate(csv_data):
        host = obj.get("hostname",None)
        
        # filter machines
        if not host: continue
        if host in seen:
            print(f"Duplicate hostname {host} on row {i+1} - skipped")
            continue
        seen.add(host)

        # create machine dict
        mach = _parse_fields(obj,'rs')
        if obj.get('folder_path',None):
            mach['folder_path'] = obj['folder_path']

        rsrs.append(mach)
        
    # Once all resources added, add pamUsers
    seen: set[str] = set()
    for i,obj in enumerate(csv_data):
        username = obj["username"]
        password = obj.get("password","")
        user_path = obj["user_path"]
        
        if not username: continue
        if username in seen:
            print(f"Duplicate username {username} on row {i+1} - skipped")
            continue
        seen.add(username)
        
        user = {"title":obj.get('title',username), "login": username, "password": password}
        if obj.get('folder_path',None):
            user['folder_path'] = obj['folder_path']
        user.update(_parse_fields(obj,'usr'))
            
        # Map user to resource
        for rs in rsrs:
            if rs['title'] == user_path:
                rs['users'].append(user)
        

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


def prepare_template(template: Dict[str, Any]) -> None:
    """ Prepare JSON template - populate missing defaults """
    tdic = DEFAULT_IMPORT_TEMPLATE
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
    tmpl = DEFAULT_IMPORT_TEMPLATE
    if args.template_file:
        tmpl = _load_template(args.template_file)
        prepare_template(tmpl)
    print(f"Processing {len(rows)} servers")

    data = _gen_data(rows, tmpl, args.prefix_names)
    write_import_json(data, args.output_file)
    print(f"Import with `pam project import -f={args.output_file}")


if __name__ == "__main__":
    main()
