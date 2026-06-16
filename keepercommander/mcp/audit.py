#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""Structured audit logging for MCP tool invocations.

Every tool call is recorded to a dedicated logger and appended (best-effort) to a
JSON-lines file under the Keeper config directory, so the human can review what an
agent did. Argument values are intentionally NOT recorded — only metadata — to avoid
writing secret material to disk.
"""

import datetime
import json
import logging

from .. import utils

logger = logging.getLogger('keepercommander.mcp.audit')

AUDIT_FILENAME = 'mcp_audit.log'


def record_tool_call(client_name, client_id, tool_name, status, detail=None):
    # type: (str, str, str, str, str) -> None
    """Record a single MCP tool invocation.

    status: 'allowed', 'denied', or 'error'. ``detail`` is a short non-sensitive note
    (e.g. a denial reason or a record UID), never argument values.
    """
    entry = {
        'ts': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'client_id': client_id,
        'client_name': client_name,
        'tool': tool_name,
        'status': status,
    }
    if detail:
        entry['detail'] = detail

    logger.info('mcp tool call: %s', entry)

    try:
        path = utils.get_default_path() / AUDIT_FILENAME
        with open(path, 'a', encoding='utf-8') as fd:
            fd.write(json.dumps(entry) + '\n')
        utils.set_file_permissions(str(path))
    except Exception as e:
        logger.debug('Unable to write MCP audit log: %s', e)
