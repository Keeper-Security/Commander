#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#


import argparse

from ..base import suppress_exit, raise_parse_exception, report_output_parser


domain_parser = argparse.ArgumentParser(prog='domain', description='Manage enterprise domains')
domain_parser.error = raise_parse_exception
domain_parser.exit = suppress_exit

domain_subparsers = domain_parser.add_subparsers(
    dest='subcommand', help='Domain subcommands', metavar='{list,reserve,alias}',
)


domain_list_parser = domain_subparsers.add_parser(
    'list', parents=[report_output_parser],
    help='List all reserved domains for the enterprise',
    description='List all reserved domains for the enterprise.',
)
domain_list_parser.error = raise_parse_exception
domain_list_parser.exit = suppress_exit


domain_reserve_parser = domain_subparsers.add_parser(
    'reserve',
    formatter_class=argparse.RawTextHelpFormatter,
    help='Reserve and manage domains',
    description=(
        'Reserve and manage domains for the enterprise.\n\n'
        'Process:\n'
        ' 1. Use --action token to get DNS verification token\n'
        ' 2. Add TXT record to your DNS\n'
        ' 3. Use --action add to complete reservation\n'
        ' 4. Use --action delete to remove domain'
    ),
)
domain_reserve_parser.add_argument(
    '--action', dest='action', required=True,
    choices=['token', 'add', 'delete'],
    help='Action to perform: token (get verification token), add (add domain after verification), delete (remove domain)',
)
domain_reserve_parser.add_argument('--domain', dest='domain', required=True,
                                    help='Domain name to reserve')
domain_reserve_parser.add_argument('--format', dest='format', action='store', choices=['text', 'json'],
                                    default='text', help='Output format.')
domain_reserve_parser.add_argument('--force', dest='force', action='store_true',
                                    help='Skip confirmation prompt for delete action')
domain_reserve_parser.error = raise_parse_exception
domain_reserve_parser.exit = suppress_exit


domain_alias_parser = domain_subparsers.add_parser(
    'alias',
    help='Manage domain aliases for the enterprise',
    description='Manage domain aliases for the enterprise.',
)
domain_alias_parser.error = raise_parse_exception
domain_alias_parser.exit = suppress_exit

domain_alias_subparsers = domain_alias_parser.add_subparsers(
    dest='alias_subcommand', help='Alias subcommands', metavar='{list,create,delete}',
)


domain_alias_list_parser = domain_alias_subparsers.add_parser(
    'list', parents=[report_output_parser],
    help='List domain aliases for the enterprise',
    description='List domain aliases for the enterprise.',
)
domain_alias_list_parser.error = raise_parse_exception
domain_alias_list_parser.exit = suppress_exit


domain_alias_create_parser = domain_alias_subparsers.add_parser(
    'create',
    formatter_class=argparse.RawTextHelpFormatter,
    help='Create domain aliases for the enterprise',
    description=(
        'Create aliases for domains owned by the enterprise.\n\n'
        'The enterprise must own the domain before an alias can be created.\n'
        'Requires Admin with "Manage Users" permission.'
    ),
)
domain_alias_create_parser.add_argument(
    '--domain', dest='domain', required=True,
    help='Domain name to create alias for (must be owned by the enterprise)',
)
domain_alias_create_parser.add_argument(
    '--alias', dest='alias', required=True, action='append',
    help='Alias to create for the domain (can be specified multiple times)',
)
domain_alias_create_parser.add_argument(
    '--format', dest='format', action='store', choices=['text', 'json'],
    default='text', help='Output format.',
)
domain_alias_create_parser.error = raise_parse_exception
domain_alias_create_parser.exit = suppress_exit


domain_alias_delete_parser = domain_alias_subparsers.add_parser(
    'delete',
    formatter_class=argparse.RawTextHelpFormatter,
    help='Delete domain aliases for the enterprise',
    description=(
        'Delete aliases for domains owned by the enterprise.\n\n'
        'Only previously created aliases can be deleted.\n'
        'Requires Admin with "Manage Users" permission.'
    ),
)
domain_alias_delete_parser.add_argument(
    '--domain', dest='domain', required=True,
    help='Domain name whose alias to delete',
)
domain_alias_delete_parser.add_argument(
    '--alias', dest='alias', required=True, action='append',
    help='Alias to delete (can be specified multiple times)',
)
domain_alias_delete_parser.add_argument(
    '--format', dest='format', action='store', choices=['text', 'json'],
    default='text', help='Output format.',
)
domain_alias_delete_parser.add_argument(
    '-f', '--force', dest='force', action='store_true',
    help='Skip confirmation prompt',
)
domain_alias_delete_parser.error = raise_parse_exception
domain_alias_delete_parser.exit = suppress_exit
