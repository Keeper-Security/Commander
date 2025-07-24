#!/usr/bin/env python3
"""
Convert LastPass shared folder membership format to Keeper format.

This script converts shared folder data from LastPass (getsfdata format)
to Keeper's shared folder format with separate teams section.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Dict, Any


def convert_folder_name(lastpass_name: str) -> str:
    """
    Convert LastPass folder name to Keeper format.
    Keeper uses "Shared-" prefix format.
    """
    if not lastpass_name.startswith("Shared-"):
        return f"Shared-{lastpass_name}"
    return lastpass_name


def convert_lastpass_to_keeper(lastpass_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert LastPass shared folder data to Keeper format.

    Args:
        lastpass_data: Dictionary with folder IDs as keys and folder data as values

    Returns:
        Dictionary in Keeper format with teams and shared_folders sections
    """
    # Track teams and their members
    teams = defaultdict(set)  # team_name -> set of member emails
    shared_folders = []

    for folder_id, folder_data in lastpass_data.items():
        # Skip deleted folders
        if folder_data.get("deleted", False):
            continue

        folder_name = folder_data.get("sharedfoldername", f"Folder-{folder_id}")
        keeper_folder_name = convert_folder_name(folder_name)

        # Track permissions and groups for this folder
        permissions = []
        folder_groups = set()  # Groups that have permissions in this folder

        users = folder_data.get("users", [])
        for entry in users:
            # Skip deleted entries
            if entry.get("deletedstatus", "0") == "1":
                continue

            username = entry.get("username")
            if not username:
                print(f"Warning: Skipping entry with no username in folder {folder_name}", file=sys.stderr)
                continue

            readonly = entry.get("readonly", "1") == "1"
            can_administer = entry.get("can_administer", "0") == "1"
            manage_records = not readonly or can_administer

            if "group_name" in entry:
                # This is a group permission entry
                group_name = entry["group_name"]

                # Add user to the team
                teams[group_name].add(username)

                # Add group permission only once per folder
                if group_name not in folder_groups:
                    folder_groups.add(group_name)
                    permissions.append({
                        "name": group_name,
                        "manage_users": can_administer,
                        "manage_records": manage_records
                    })
            else:
                # This is a direct user permission entry
                permissions.append({
                    "name": username,
                    "manage_users": can_administer,
                    "manage_records": manage_records
                })

        # Only add folder if it has active permissions
        if permissions:
            shared_folders.append({
                "path": keeper_folder_name,
                "permissions": permissions
            })

    # Convert teams defaultdict to list format
    teams_list = []
    for team_name, members in teams.items():
        teams_list.append({
            "name": team_name,
            "members": sorted(list(members))  # Sort for consistent output
        })

    # Sort teams by name for consistent output
    teams_list.sort(key=lambda x: x["name"])

    result = {
        "shared_folders": shared_folders
    }

    # Only add teams section if there are teams
    if teams_list:
        result["teams"] = teams_list

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Convert LastPass shared folder format to Keeper format with teams"
    )
    parser.add_argument(
        "input_file",
        help="Input LastPass JSON file (getsfdata format)"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty print the output JSON"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file if it exists"
    )

    args = parser.parse_args()

    # Fixed output filename
    output_file = "shared_folder_membership.json"

    try:
        # Check if output file exists
        if os.path.exists(output_file) and not args.force:
            print(f"Error: Output file '{output_file}' already exists!", file=sys.stderr)
            print(f"Use --force to overwrite the existing file", file=sys.stderr)
            sys.exit(1)

        # Read input file
        with open(args.input_file, 'r', encoding='utf-8') as f:
            lastpass_data = json.load(f)

        # Validate input format
        if not isinstance(lastpass_data, dict):
            print("Error: Input file should contain a JSON object with folder IDs as keys", file=sys.stderr)
            sys.exit(1)

        # Convert to Keeper format
        keeper_data = convert_lastpass_to_keeper(lastpass_data)

        # Write output file
        with open(output_file, 'w', encoding='utf-8') as f:
            if args.pretty:
                json.dump(keeper_data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(keeper_data, f, ensure_ascii=False)

        # Print summary
        folder_count = len(keeper_data["shared_folders"])
        team_count = len(keeper_data.get("teams", []))
        total_permissions = sum(len(folder["permissions"]) for folder in keeper_data["shared_folders"])
        total_team_members = sum(len(team["members"]) for team in keeper_data.get("teams", []))

        print(f"Conversion completed successfully!")
        print(f"Converted {folder_count} shared folders with {total_permissions} total permissions")
        print(f"Created {team_count} teams with {total_team_members} total team memberships")
        print(f"Output written to: {output_file}")

    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def print_conversion_info():
    """Print information about the conversion process."""
    print("LastPass to Keeper Shared Folder Converter")
    print("=" * 50)
    print()
    print("This script converts LastPass shared folder data to Keeper format.")
    print()
    print("Key Features:")
    print("- Extracts teams from group permissions and creates separate teams section")
    print("- Handles both direct user permissions and group-based permissions")
    print("- Each team appears only once per shared folder")
    print("- Teams are automatically populated with members based on group permissions")
    print()
    print("LastPass Input Structure:")
    print("- Folder entries contain 'users' array")
    print("- Group permissions have both 'username' and 'group_name' fields")
    print("- Direct user permissions have only 'username' field")
    print()
    print("Keeper Output Structure:")
    print("- 'teams' section with team names and member lists")
    print("- 'shared_folders' section with permissions referencing teams by name")
    print()
    print("Permission Mapping:")
    print("- LastPass 'readonly': '0' -> Keeper 'manage_records': true")
    print("- LastPass 'readonly': '1' -> Keeper 'manage_records': false")
    print("- LastPass 'can_administer': '1' -> Keeper 'manage_users': true")
    print("- Admins get manage_records=true regardless of readonly status")
    print()
    print("Usage:")
    print("  python converter.py input.json [--pretty] [--force]")
    print()
    print("Options:")
    print("  --pretty    Pretty print the JSON output")
    print("  --force     Overwrite shared_folder_membership.json if it exists")
    print()
    print("Output: Always creates 'shared_folder_membership.json'")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_conversion_info()
    else:
        main()