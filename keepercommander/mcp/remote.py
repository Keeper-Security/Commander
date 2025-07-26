#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander MCP Server
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Remote MCP server implementation (WebSocket transport)."""

import asyncio
import json
import logging
import ssl
import secrets
import datetime
from typing import Dict, Any, Optional, List, Set
from pathlib import Path

try:
    import websockets
    from websockets.server import WebSocketServerProtocol
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    WebSocketServerProtocol = Any

from mcp.server.stdio import stdio_server
from ..display import bcolors


class RemoteMCPServer:
    """Remote MCP server with WebSocket transport"""
    
    def __init__(self, server, config: Dict[str, Any]):
        self.server = server
        self.config = config
        self.remote_config = config.get('remote_access', {})
        self._load_auth_tokens()
        self.active_connections: Set[WebSocketServerProtocol] = set()
        self.logger = logging.getLogger(__name__)
    
    def _load_auth_tokens(self):
        """Load authentication tokens from config"""
        self.auth_tokens = {}
        for token_info in self.remote_config.get('auth_tokens', []):
            if isinstance(token_info, dict):
                token = token_info.get('token')
                name = token_info.get('name', 'unknown')
                if token:
                    self.auth_tokens[token] = {
                        'name': name,
                        'created': token_info.get('created', str(datetime.datetime.now().isoformat()))
                    }
    
    async def start_remote(self, host: str = '0.0.0.0', port: Optional[int] = None):
        """Start remote MCP server"""
        if not HAS_WEBSOCKETS:
            raise ImportError("websockets library not installed. Install with: pip install websockets")
        
        if not self.remote_config.get('enabled', False):
            raise RuntimeError("Remote access is not enabled. Enable with: mcp-server remote enable")
        
        # Use port from config if not specified
        if port is None:
            port = self.remote_config.get('port', 3001)
        
        # Set up TLS if configured
        ssl_context = None
        tls_config = self.remote_config.get('tls', {})
        if tls_config.get('enabled', False):
            ssl_context = self._create_ssl_context(tls_config)
        
        # Log startup info
        protocol = "wss" if ssl_context else "ws"
        self.logger.info(f"Starting remote MCP server on {protocol}://{host}:{port}")
        print(f"\n{bcolors.OKGREEN}Starting remote MCP server...{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}Protocol: {protocol}://{host}:{port}{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}Active tokens: {len(self.auth_tokens)}{bcolors.ENDC}")
        
        if not ssl_context:
            print(f"{bcolors.WARNING}WARNING: TLS is not enabled. Connection will not be encrypted.{bcolors.ENDC}")
        
        # Start WebSocket server
        async with websockets.serve(
            self._handle_connection,
            host,
            port,
            ssl=ssl_context,
            ping_interval=30,
            ping_timeout=10
        ):
            print(f"\n{bcolors.OKGREEN}Remote MCP server is running. Press Ctrl+C to stop.{bcolors.ENDC}")
            await asyncio.Future()  # Run forever
    
    async def _handle_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle a new WebSocket connection"""
        client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        self.logger.info(f"New connection from {client_info}")
        
        try:
            # Authenticate the connection
            authenticated = await self._authenticate_connection(websocket)
            if not authenticated:
                self.logger.warning(f"Authentication failed for {client_info}")
                await websocket.close(code=1008, reason="Authentication failed")
                return
            
            # Add to active connections
            self.active_connections.add(websocket)
            self.logger.info(f"Client {client_info} authenticated successfully")
            
            # Create read/write streams for the MCP server
            class WebSocketReadStream:
                def __init__(self, ws):
                    self.ws = ws
                
                def __aiter__(self):
                    return self
                
                async def __anext__(self):
                    try:
                        message = await self.ws.recv()
                        if isinstance(message, str):
                            return message.encode('utf-8')
                        return message
                    except websockets.exceptions.ConnectionClosed:
                        raise StopAsyncIteration
            
            class WebSocketWriteStream:
                def __init__(self, ws):
                    self.ws = ws
                
                async def write(self, data: bytes):
                    await self.ws.send(data.decode('utf-8'))
                
                async def close(self):
                    pass
            
            # Run the MCP server for this connection
            read_stream = WebSocketReadStream(websocket)
            write_stream = WebSocketWriteStream(websocket)
            await self.server.run(read_stream, write_stream)
            
        except websockets.exceptions.ConnectionClosed:
            self.logger.info(f"Client {client_info} disconnected")
        except Exception as e:
            self.logger.error(f"Error handling connection from {client_info}: {e}")
        finally:
            self.active_connections.discard(websocket)
    
    async def _authenticate_connection(self, websocket: WebSocketServerProtocol) -> bool:
        """Authenticate a WebSocket connection"""
        try:
            # Send authentication challenge
            await websocket.send(json.dumps({
                "type": "auth_required",
                "message": "Please provide authentication token"
            }))
            
            # Wait for authentication response (with timeout)
            auth_message = await asyncio.wait_for(websocket.recv(), timeout=30.0)
            auth_data = json.loads(auth_message)
            
            token = auth_data.get("token")
            if not token:
                return False
            
            # Validate token
            if token in self.auth_tokens:
                token_info = self.auth_tokens[token]
                await websocket.send(json.dumps({
                    "type": "auth_success",
                    "message": f"Authenticated as {token_info['name']}"
                }))
                return True
            else:
                return False
                
        except (json.JSONDecodeError, asyncio.TimeoutError, KeyError):
            return False
    
    def _create_ssl_context(self, tls_config: Dict[str, Any]) -> ssl.SSLContext:
        """Create SSL context for TLS"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        cert_file = tls_config.get('cert_file')
        key_file = tls_config.get('key_file')
        
        if not cert_file or not key_file:
            raise ValueError("TLS enabled but cert_file or key_file not specified")
        
        cert_path = Path(cert_file).expanduser()
        key_path = Path(key_file).expanduser()
        
        if not cert_path.exists():
            raise FileNotFoundError(f"Certificate file not found: {cert_path}")
        if not key_path.exists():
            raise FileNotFoundError(f"Key file not found: {key_path}")
        
        context.load_cert_chain(str(cert_path), str(key_path))
        return context
    
    def generate_auth_token(self, name: str) -> Dict[str, str]:
        """Generate a new authentication token"""
        token = secrets.token_urlsafe(32)
        token_info = {
            'name': name,
            'token': token,
            'created': datetime.datetime.now().isoformat()
        }
        
        # Add to current session
        self.auth_tokens[token] = {
            'name': name,
            'created': token_info['created']
        }
        
        return token_info
    
    def list_auth_tokens(self) -> List[Dict[str, str]]:
        """List all auth tokens (masked)"""
        tokens = []
        for token, info in self.auth_tokens.items():
            tokens.append({
                'name': info['name'],
                'token_preview': f"{token[:8]}...",
                'created': info['created']
            })
        return tokens
    
    def revoke_auth_token(self, name: str) -> bool:
        """Revoke an auth token by name"""
        for token, info in list(self.auth_tokens.items()):
            if info['name'] == name:
                del self.auth_tokens[token]
                return True
        return False
    
    def get_active_connections(self) -> int:
        """Get number of active connections"""
        return len(self.active_connections)