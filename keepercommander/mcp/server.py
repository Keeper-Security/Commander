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
"""stdio MCP server for Keeper Commander.

Launched by an AI client as ``keeper mcp start --client-token <token>``. It loads the
approval/capability configuration from the dedicated vault record, validates the client
token, and exposes only the tools the client has been granted. Scope, self-protection,
and guardrails are enforced on every call, and the configuration is re-checked on a TTL
so revocation takes effect without a restart.
"""

import asyncio
import json
import logging
import time

from . import audit, capabilities as caps_module, config as config_module
from .guardrails import MCPAccessError
from ..params import KeeperParams

logger = logging.getLogger('keepercommander.mcp.server')

SERVER_NAME = 'keeper-commander'
DEFAULT_REFRESH_TTL = 60  # seconds between config re-checks (revocation latency)


class MCPServerError(Exception):
    pass


class CommanderMCPServer:
    def __init__(self, params, client_token, refresh_ttl=DEFAULT_REFRESH_TTL):
        # type: (KeeperParams, str, int) -> None
        self.params = params
        self._token = client_token
        self._refresh_ttl = refresh_ttl
        self._last_refresh = 0.0
        self.config = None     # type: config_module.MCPConfig
        self.client = None     # type: config_module.MCPClient
        self._reload(force=True)

    # ----- config lifecycle -----
    def _reload(self, force=False):  # type: (bool) -> None
        now = time.monotonic()
        if not force and (now - self._last_refresh) < self._refresh_ttl:
            return
        if not force:
            # Pick up revocations/toggles made in another session.
            from .. import api
            try:
                api.sync_down(self.params)
            except Exception as e:
                logger.debug('MCP config refresh sync_down failed: %s', e)
        self.config = config_module.load_config(self.params)
        self.client = self.config.validate_token(self._token)
        self._last_refresh = now

    def _ensure_authorized(self):  # type: () -> config_module.MCPClient
        """Re-validate master toggle + client on the TTL; raise if access is gone."""
        self._reload(force=False)
        if not self.config.enabled:
            raise MCPAccessError('AI agent access is disabled.')
        if not self.client or not self.client.is_active():
            raise MCPAccessError('This client is not authorized (revoked, expired, or unknown).')
        return self.client

    def effective_capabilities(self):  # type: () -> dict
        return self.config.effective_capabilities(self.client)

    # ----- tool dispatch -----
    def list_tool_specs(self):
        """Return (Capability, schema) pairs for currently effective capabilities."""
        effective = self.effective_capabilities()
        specs = []
        for name in caps_module.capability_names():  # preserve registry order
            if name in effective:
                cap = caps_module.get_capability(name)
                if cap:
                    specs.append(cap)
        return specs

    def call(self, tool_name, arguments):  # type: (str, dict) -> dict
        """Synchronous dispatch with full enforcement and auditing."""
        client = self._ensure_authorized()
        client_name, client_id = client.name, client.client_id
        cap = caps_module.get_capability(tool_name)
        if cap is None:
            audit.record_tool_call(client_name, client_id, tool_name, 'denied', 'unknown tool')
            raise MCPAccessError(f'Unknown tool: {tool_name}')

        grant = self.effective_capabilities().get(tool_name)
        if grant is None:
            audit.record_tool_call(client_name, client_id, tool_name, 'denied', 'capability not granted')
            raise MCPAccessError(f'Capability "{tool_name}" is not granted to this client.')

        try:
            result = cap.handler(self.params, self.config, grant, arguments or {})
            audit.record_tool_call(client_name, client_id, tool_name, 'allowed')
            return result
        except MCPAccessError as e:
            audit.record_tool_call(client_name, client_id, tool_name, 'denied', str(e))
            raise
        except Exception as e:
            logger.exception('MCP tool %s failed', tool_name)
            audit.record_tool_call(client_name, client_id, tool_name, 'error', str(e))
            raise


def _build_mcp_app(server):  # type: (CommanderMCPServer) -> object
    """Construct the low-level MCP Server object and register handlers."""
    try:
        import mcp.types as types
        from mcp.server.lowlevel import Server
    except ImportError as e:
        raise MCPServerError(
            'The "mcp" package is required for "mcp start". Install it with: pip install mcp'
        ) from e

    app = Server(SERVER_NAME)

    @app.list_tools()
    async def list_tools():
        return [
            types.Tool(name=cap.tool_name, description=cap.description, inputSchema=cap.input_schema)
            for cap in server.list_tool_specs()
        ]

    @app.call_tool()
    async def call_tool(name, arguments):
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, server.call, name, arguments)
            text = json.dumps(result, default=str)
            return [types.TextContent(type='text', text=text)]
        except MCPAccessError as e:
            return [types.TextContent(type='text', text=json.dumps({'error': str(e)}))]

    return app


def serve(params, client_token, refresh_ttl=DEFAULT_REFRESH_TTL):
    # type: (KeeperParams, str, int) -> None
    """Run the stdio MCP server. Blocks until the client disconnects."""
    server = CommanderMCPServer(params, client_token, refresh_ttl=refresh_ttl)
    if not server.config.enabled:
        raise MCPServerError('AI agent access is disabled. Enable it with: mcp enable')
    if not server.client:
        raise MCPServerError('Invalid or revoked client token.')

    app = _build_mcp_app(server)

    from mcp.server.stdio import stdio_server

    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    logger.info('Starting Keeper Commander MCP server for client "%s"', server.client.name)
    asyncio.run(_run())
