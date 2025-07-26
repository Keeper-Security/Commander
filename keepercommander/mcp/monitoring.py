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

"""Monitoring and metrics for MCP server."""

import time
import json
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from contextlib import contextmanager
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

try:
    from prometheus_client import Counter, Histogram, Gauge, Info
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    # Dummy implementations if prometheus-client not available
    class Counter:
        def __init__(self, *args, **kwargs): pass
        def labels(self, **kwargs): return self
        def inc(self, amount=1): pass
    
    class Histogram:
        def __init__(self, *args, **kwargs): pass
        def labels(self, **kwargs): return self
        def observe(self, value): pass
    
    class Gauge:
        def __init__(self, *args, **kwargs): pass
        def inc(self): pass
        def dec(self): pass
        def set(self, value): pass
    
    class Info:
        def __init__(self, *args, **kwargs): pass
        def info(self, value): pass


class MCPMetrics:
    """Metrics collector for MCP server operations"""
    
    def __init__(self):
        # Request metrics
        self.request_count = Counter(
            'mcp_requests_total',
            'Total MCP requests',
            ['method', 'tool', 'status']
        )
        
        self.request_duration = Histogram(
            'mcp_request_duration_seconds',
            'MCP request duration',
            ['method', 'tool'],
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        )
        
        # Connection metrics
        self.active_connections = Gauge(
            'mcp_active_connections',
            'Number of active MCP connections'
        )
        
        self.total_connections = Counter(
            'mcp_connections_total',
            'Total MCP connections',
            ['transport']  # 'stdio' or 'websocket'
        )
        
        # Error metrics
        self.command_errors = Counter(
            'mcp_command_errors_total',
            'Total command execution errors',
            ['command', 'error_type']
        )
        
        self.permission_denials = Counter(
            'mcp_permission_denials_total',
            'Total permission denials',
            ['command']
        )
        
        self.rate_limit_hits = Counter(
            'mcp_rate_limit_hits_total',
            'Total rate limit hits',
            ['command', 'limit_type']  # 'global' or 'command'
        )
        
        # Server info
        self.server_info = Info(
            'mcp_server',
            'MCP server information'
        )
        
        # Initialize server info
        self.server_info.info({
            'version': '1.0.0',
            'protocol': 'mcp-1.0'
        })
        
        # In-memory stats for status command
        self.stats = {
            'start_time': datetime.utcnow().isoformat(),
            'total_requests': 0,
            'total_errors': 0,
            'commands_executed': {},
            'recent_errors': []  # Keep last 10 errors
        }
    
    @contextmanager
    def track_request(self, method: str, tool: str):
        """Context manager to track request metrics"""
        start_time = time.time()
        self.stats['total_requests'] += 1
        
        if tool not in self.stats['commands_executed']:
            self.stats['commands_executed'][tool] = 0
        self.stats['commands_executed'][tool] += 1
        
        try:
            yield
            self.request_count.labels(method, tool, 'success').inc()
        except Exception as e:
            self.request_count.labels(method, tool, 'error').inc()
            self.command_errors.labels(tool, type(e).__name__).inc()
            self.stats['total_errors'] += 1
            
            # Record error for status
            error_info = {
                'timestamp': datetime.utcnow().isoformat(),
                'command': tool,
                'error_type': type(e).__name__,
                'message': str(e)
            }
            self.stats['recent_errors'].append(error_info)
            if len(self.stats['recent_errors']) > 10:
                self.stats['recent_errors'].pop(0)
            
            raise
        finally:
            duration = time.time() - start_time
            self.request_duration.labels(method, tool).observe(duration)
    
    def track_connection(self, transport: str):
        """Track new connection"""
        self.total_connections.labels(transport).inc()
        self.active_connections.inc()
    
    def track_disconnection(self):
        """Track connection closure"""
        self.active_connections.dec()
    
    def track_permission_denial(self, command: str):
        """Track permission denial"""
        self.permission_denials.labels(command).inc()
    
    def track_rate_limit(self, command: str, limit_type: str):
        """Track rate limit hit"""
        self.rate_limit_hits.labels(command, limit_type).inc()
    
    def get_status(self) -> Dict[str, Any]:
        """Get current server status and metrics"""
        uptime_seconds = (datetime.utcnow() - datetime.fromisoformat(self.stats['start_time'])).total_seconds()
        
        return {
            'server': {
                'version': '1.0.0',
                'protocol': 'mcp-1.0',
                'start_time': self.stats['start_time'],
                'uptime_seconds': uptime_seconds,
                'prometheus_enabled': PROMETHEUS_AVAILABLE
            },
            'metrics': {
                'total_requests': self.stats['total_requests'],
                'total_errors': self.stats['total_errors'],
                'error_rate': self.stats['total_errors'] / max(1, self.stats['total_requests']),
                'commands_executed': self.stats['commands_executed'],
                'recent_errors': self.stats['recent_errors']
            }
        }


class MCPLogger:
    """Structured logging for MCP server with rotation support"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('logging', {})
        self.enabled = self.config.get('enabled', True)
        self.level = self.config.get('level', 'info').upper()
        
        # Set up logger
        self.logger = logging.getLogger('keepercommander.mcp')
        self.logger.setLevel(getattr(logging, self.level))
        
        # Clear existing handlers to avoid duplicates
        self.logger.handlers = []
        
        # Add file handler if specified
        log_file = self.config.get('file')
        if log_file and self.enabled:
            # Expand path
            log_path = Path(log_file).expanduser()
            
            # Create log directory if it doesn't exist
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Get rotation configuration
            rotation_config = self.config.get('rotation', {})
            rotation_type = rotation_config.get('type', 'size')  # 'size' or 'time'
            
            # Create appropriate handler based on rotation type
            if rotation_type == 'time':
                # Time-based rotation
                when = rotation_config.get('when', 'midnight')  # midnight, H, D, W0-W6
                interval = rotation_config.get('interval', 1)
                backup_count = rotation_config.get('backup_count', 7)
                
                handler = TimedRotatingFileHandler(
                    str(log_path),
                    when=when,
                    interval=interval,
                    backupCount=backup_count,
                    encoding='utf-8'
                )
                # Set suffix for rotated files
                handler.suffix = rotation_config.get('suffix', '%Y-%m-%d')
            else:
                # Size-based rotation (default)
                max_bytes = rotation_config.get('max_size_mb', 10) * 1024 * 1024  # Default 10MB
                backup_count = rotation_config.get('backup_count', 5)
                
                handler = RotatingFileHandler(
                    str(log_path),
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding='utf-8'
                )
            
            # Set formatter
            format_string = self.config.get('format', 
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            formatter = logging.Formatter(format_string)
            handler.setFormatter(formatter)
            
            # Add handler to logger
            self.logger.addHandler(handler)
            
            # Also add console handler for warnings and above
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.WARNING)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
    
    def log_request(self, method: str, tool: str, arguments: Dict[str, Any], session_id: str):
        """Log incoming request"""
        if not self.enabled:
            return
        
        self.logger.info(
            "MCP Request",
            extra={
                'method': method,
                'tool': tool,
                'session_id': session_id,
                'arguments': json.dumps(arguments) if arguments else '{}'
            }
        )
    
    def log_response(self, method: str, tool: str, success: bool, duration: float, session_id: str):
        """Log response"""
        if not self.enabled:
            return
        
        self.logger.info(
            "MCP Response",
            extra={
                'method': method,
                'tool': tool,
                'success': success,
                'duration_ms': duration * 1000,
                'session_id': session_id
            }
        )
    
    def log_error(self, method: str, tool: str, error: Exception, session_id: str):
        """Log error"""
        self.logger.error(
            f"MCP Error: {str(error)}",
            extra={
                'method': method,
                'tool': tool,
                'error_type': type(error).__name__,
                'session_id': session_id
            },
            exc_info=True
        )