#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Contact: ops@keepersecurity.com
#

import asyncio
import json
import logging
import os
import ssl
import threading
import time
from enum import Enum
from typing import Optional, Callable, Tuple, Dict

from keeper_secrets_manager_core.utils import bytes_to_base64
from ...utils import base64_url_decode
from .router_helper import get_router_ws_url
from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens


class WebsocketMessageType(Enum):
    # Does not include all types
    CTL_STATUS = "ctl_status"
    GW_RESPONSE = "gw_response"

try:
    from websockets.asyncio.client import connect as websockets_connect
    from websockets.exceptions import ConnectionClosed, InvalidURI, InvalidHandshake
    WEBSOCKETS_VERSION = "asyncio"
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    try:
        # Fallback to websockets 11.0.3 legacy implementation
        from websockets import connect as websockets_connect
        from websockets.exceptions import ConnectionClosed, InvalidURI, InvalidHandshake
        WEBSOCKETS_VERSION = "legacy"
        WEBSOCKETS_AVAILABLE = True
    except ImportError:
        WEBSOCKETS_AVAILABLE = False
        WEBSOCKETS_VERSION = None
        websockets_connect = None
        ConnectionClosed = None
        logging.debug("WebSocket library not available - streaming features will not work")

VERIFY_SSL = bool(os.environ.get("VERIFY_SSL", "TRUE") == "TRUE")


class WebSocketListener:
    def __init__(self, params, conversation_id: str, timeout: int = 300):
        self.params = params
        self.conversation_id = conversation_id
        self.timeout = timeout
        self.stop_event = threading.Event()
        self.message_handler = None  # type: Optional[Callable[[Dict], Optional[bool]]]

    def set_message_handler(self, handler: Callable[[Dict], Optional[bool]]):
        self.message_handler = handler

    async def listen(self) -> bool:
        if not WEBSOCKETS_AVAILABLE:
            logging.warning("WebSocket library not available - streaming will not work")
            return False

        # Get WebSocket URL
        ws_endpoint = get_router_ws_url(self.params) + "/api/user/client"
        logging.debug(f"Connecting to WebSocket: {ws_endpoint}")

        # Prepare authentication headers
        encrypted_session_token, encrypted_transmission_key, _ = get_keeper_tokens(self.params)
        headers = {
            'TransmissionKey': bytes_to_base64(encrypted_transmission_key),
            'Authorization': f'KeeperUser {bytes_to_base64(encrypted_session_token)}',
        }

        # Set up SSL context
        ssl_context = None
        if ws_endpoint.startswith('wss://'):
            ssl_context = ssl.create_default_context()
            if not VERIFY_SSL:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

        return await self._connect_and_listen(ws_endpoint, headers, ssl_context)

    async def _connect_and_listen(self, ws_endpoint: str, headers: dict, ssl_context) -> bool:
        base_kwargs = {
            "ping_interval": 20,
            "ping_timeout": 20,
            "close_timeout": 30
        }

        try:
            if WEBSOCKETS_VERSION == "asyncio":
                connect_kwargs = {
                    **base_kwargs,
                    "additional_headers": headers
                }

                if ssl_context:
                    try:
                        async with websockets_connect(ws_endpoint, ssl_context=ssl_context, **connect_kwargs) as websocket:
                            logging.debug("WebSocket connected (asyncio, ssl_context)")
                            return await self._handle_messages(websocket)
                    except TypeError as e:
                        if "ssl_context" in str(e):
                            logging.debug("ssl_context not supported, trying ssl parameter")
                            async with websockets_connect(ws_endpoint, ssl=ssl_context, **connect_kwargs) as websocket:
                                logging.debug("WebSocket connected (asyncio, ssl)")
                                return await self._handle_messages(websocket)
                        else:
                            raise
                else:
                    async with websockets_connect(ws_endpoint, **connect_kwargs) as websocket:
                        logging.debug("WebSocket connected (asyncio, no ssl)")
                        return await self._handle_messages(websocket)

            elif WEBSOCKETS_VERSION == "legacy":
                connect_kwargs = {
                    **base_kwargs,
                    "extra_headers": headers
                }

                if ssl_context:
                    async with websockets_connect(ws_endpoint, ssl=ssl_context, **connect_kwargs) as websocket:
                        logging.debug("WebSocket connected (legacy, ssl)")
                        return await self._handle_messages(websocket)
                else:
                    async with websockets_connect(ws_endpoint, **connect_kwargs) as websocket:
                        logging.debug("WebSocket connected (legacy, no ssl)")
                        return await self._handle_messages(websocket)
            else:
                raise Exception("No compatible websockets version available")

        except Exception as e:
            logging.error(f"WebSocket connection error: {e}")
            return False

    async def _handle_messages(self, websocket) -> bool:
        start_time = time.time()
        should_close = False

        try:
            while time.time() - start_time < self.timeout:
                if self.stop_event.is_set():
                    logging.debug("Stop event received, closing WebSocket")
                    break

                if should_close:
                    logging.debug("Handler requested close, exiting message loop")
                    break

                try:
                    message_text = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    logging.debug(f"WebSocket received: {message_text[:200]}...")

                    response_data = json.loads(message_text)
                    messages = response_data if isinstance(response_data, list) else [response_data]

                    for message in messages:
                        msg_conversation_id = base64_url_decode(message.get('conversationId'))
                        if msg_conversation_id != base64_url_decode(self.conversation_id):
                            continue

                        # Check for CTL_STATUS with OFFLINE - pass to handler and close connection
                        message_type = message.get('type')
                        if message_type == WebsocketMessageType.CTL_STATUS.value:
                            from ...discovery_common.types import ControllerStatus
                            controller_status = message.get('controllerStatus')
                            if controller_status == ControllerStatus.OFFLINE.value:
                                logging.warning("Received CTL_STATUS with OFFLINE status - closing WebSocket")
                                # Let the message handler process the offline status before closing
                                if self.message_handler:
                                    self.message_handler(message)
                                should_close = True
                                break

                        if self.message_handler:
                            should_stop = self.message_handler(message)
                            if should_stop is True:
                                logging.debug("Message handler returned True - closing WebSocket")
                                should_close = True
                                break
                            elif should_stop is False:
                                logging.debug("Message handler returned False - closing WebSocket with error")
                                should_close = True
                                break

                except asyncio.TimeoutError:
                    # No message within timeout, continue loop
                    continue
                except ConnectionClosed:
                    logging.debug("WebSocket connection closed")
                    break
                except Exception as e:
                    logging.error(f"Error processing WebSocket message: {e}")
                    continue

        except Exception as e:
            logging.error(f"Error in message handling loop: {e}")
            return False
        finally:
            logging.debug("WebSocket message handler completed")

        return True

    def stop(self):
        self.stop_event.set()


def start_websocket_listener(
    params,
    conversation_id: str,
    message_handler: Callable[[Dict], Optional[bool]],
    timeout: int = 300
) -> Tuple[threading.Thread, threading.Event, WebSocketListener]:
    listener = WebSocketListener(params, conversation_id, timeout)
    listener.set_message_handler(message_handler)

    def run_websocket():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(listener.listen())
        except Exception as e:
            logging.error(f"WebSocket listener error: {e}")
        finally:
            loop.close()

    thread = threading.Thread(
        target=run_websocket,
        daemon=True,
        name=f"PAM-WebSocket-{conversation_id[:8]}"
    )
    thread.start()

    return thread, listener.stop_event, listener


def listen_for_conversation(
    params,
    conversation_id: str,
    on_message: Callable[[Dict], Optional[bool]],
    timeout: int = 300,
) -> bool:
    thread, stop_event, listener = start_websocket_listener(
        params, conversation_id, on_message, timeout
    )
    return True


def is_websocket_available() -> bool:
    return WEBSOCKETS_AVAILABLE
