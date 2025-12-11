#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander - Slack Integration
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Main Keeper Slack App orchestrator.
"""

import json
from typing import Optional
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from .config import Config
from .keeper_client import KeeperClient
from .commands import (
    handle_request_record,
    handle_request_folder,
    handle_one_time_share,
)
from .handlers import (
    handle_approve_action,
    handle_deny_action,
    handle_search_records,
    handle_search_folders,
    handle_search_modal_submit,
    handle_refine_search_action,
    handle_approve_pedm_request,
    handle_deny_pedm_request,
)


class KeeperSlackApp:
    """
    Keeper Commander Slack Application.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize Keeper Slack App.
        """
        print("[INFO] Initializing Keeper Commander Slack App...")
        
        # Load configuration
        self.config = Config(config_path)
        print(f"[OK] Configuration loaded")
        
        # Initialize Keeper API client
        self.keeper_client = KeeperClient(self.config.keeper)
        print(f"[OK] Keeper client initialized: {self.config.keeper.service_url}")
        
        # Initialize Slack Bolt app
        self.slack_app = App(
            token=self.config.slack.bot_token,
            signing_secret=self.config.slack.signing_secret
        )
        print(f"[OK] Slack app initialized")
        
        # Register all handlers
        self._register_commands()
        self._register_interactions()
        print(f"[OK] All handlers registered")
        
        # Initialize Socket Mode handler
        self.socket_handler = SocketModeHandler(
            app=self.slack_app,
            app_token=self.config.slack.app_token
        )
        print(f"[OK] Socket Mode handler ready")
        print(f"[INFO] Approval channel: {self.config.slack.approvals_channel_id}")
        
        # Initialize PEDM poller
        from .background import PEDMPoller
        self.pedm_poller = PEDMPoller(
            slack_client=self.slack_app.client,
            keeper_client=self.keeper_client,
            config=self.config,
            interval=120  # Poll every 2 minutes
        )
        print(f"[OK] PEDM poller initialized")
    
    def _register_commands(self):
        """Register all slash command handlers."""
        
        @self.slack_app.command("/keeper-request-record")
        def cmd_request_record(ack, body, client):
            ack()
            handle_request_record(body, client, self.config, self.keeper_client)
        
        @self.slack_app.command("/keeper-request-folder")
        def cmd_request_folder(ack, body, client):
            ack()
            handle_request_folder(body, client, self.config, self.keeper_client)
        
        @self.slack_app.command("/keeper-one-time-share")
        def cmd_one_time_share(ack, body, client):
            ack()
            handle_one_time_share(body, client, self.config, self.keeper_client)

    
    def _register_interactions(self):
        """Register all interaction handlers."""
        
        # Approval buttons
        @self.slack_app.action("approve_request")
        def action_approve(ack, body, client):
            ack()
            handle_approve_action(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("deny_request")
        def action_deny(ack, body, client):
            ack()
            handle_deny_action(body, client, self.config, self.keeper_client)
        
        # PEDM approval buttons
        @self.slack_app.action("approve_pedm_request")
        def action_approve_pedm(ack, body, client):
            ack()
            handle_approve_pedm_request(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("deny_pedm_request")
        def action_deny_pedm(ack, body, client):
            ack()
            handle_deny_pedm_request(body, client, self.config, self.keeper_client)
        
        # Search buttons
        @self.slack_app.action("search_records")
        def action_search_records(ack, body, client):
            ack()
            handle_search_records(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("search_folders")
        def action_search_folders(ack, body, client):
            ack()
            handle_search_folders(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("search_one_time_shares")
        def action_search_one_time_shares(ack, body, client):
            ack()
            handle_search_records(body, client, self.config, self.keeper_client)
        
        # Dropdown selectors on approval cards
        @self.slack_app.action("select_duration")
        def action_select_duration(ack):
            """Acknowledge duration dropdown selection."""
            ack()

        
        @self.slack_app.action("select_permission")
        def action_select_permission(ack, body, client):
            """Handle permission dropdown selection - dynamically show/hide duration."""
            ack()
            
            try:
                import json
                
                # Get selected permission
                selected_permission = body["actions"][0]["selected_option"]["value"]
                
                # Determine if duration should be shown
                PERMANENT_ONLY = ["can_share", "edit_and_share", "change_owner", "manage_users", "manage_all"]
                show_duration = selected_permission not in PERMANENT_ONLY
                
                # Check if this is a modal or a message
                if "view" in body:
                    # MODAL: Rebuild search modal
                    from .views import build_search_modal
                    
                    view = body["view"]
                    metadata = json.loads(view["private_metadata"])
                    
                    updated_modal = build_search_modal(
                        query=metadata.get("query", ""),
                        search_type=metadata.get("search_type", "record"),
                        results=metadata.get("cached_results", []),
                        approval_data=metadata,
                        loading=False,
                        show_duration=show_duration
                    )
                    
                    client.views_update(view_id=view["id"], view=updated_modal)
                    print(f"[INFO] Updated modal: show_duration={show_duration} for permission={selected_permission}")
                    
                elif "message" in body:
                    # MESSAGE: Update approval card (UID-based requests)
                    from .views import build_permission_selector_block
                    from .utils import get_duration_options
                    from .models import RequestType
                    
                    message = body["message"]
                    channel = body["channel"]["id"]
                    message_ts = message["ts"]
                    blocks = message.get("blocks", [])
                    
                    # Determine request type from header
                    request_type = RequestType.RECORD
                    for block in blocks:
                        if block.get("type") == "header":
                            header_text = block.get("text", {}).get("text", "")
                            if "Folder" in header_text:
                                request_type = RequestType.FOLDER
                            break
                    
                    # Rebuild blocks with updated duration visibility
                    new_blocks = []
                    for block in blocks:
                        block_id = block.get("block_id", "")
                        accessory = block.get("accessory", {})
                        action_id = accessory.get("action_id", "")
                        
                        # Skip old duration selector block
                        if block_id == "duration_selector" or action_id == "select_duration":
                            continue
                        
                        # Skip old permanent notice context block
                        if block.get("type") == "context":
                            elements = block.get("elements", [])
                            if elements and "Permanent Access" in elements[0].get("text", ""):
                                continue
                        
                        # After permission selector, add duration or permanent notice
                        if action_id == "select_permission":
                            new_blocks.append(block)  # Keep permission selector
                            
                            if show_duration:
                                new_blocks.append({
                                    "type": "section",
                                    "block_id": "duration_selector",
                                    "text": {"type": "mrkdwn", "text": "*Grant Access For:*"},
                                    "accessory": {
                                        "type": "static_select",
                                        "action_id": "select_duration",
                                        "options": get_duration_options(),
                                        "initial_option": {"text": {"type": "plain_text", "text": "24 hours"}, "value": "24h"}
                                    }
                                })
                            else:
                                new_blocks.append({
                                    "type": "context",
                                    "elements": [{"type": "mrkdwn", "text": "ℹ️ *Permanent Access:* This permission does not support time limits."}]
                                })
                        else:
                            new_blocks.append(block)
                    
                    # Update the message
                    client.chat_update(
                        channel=channel,
                        ts=message_ts,
                        blocks=new_blocks,
                        text="Access Request"
                    )
                    print(f"[INFO] Updated message: show_duration={show_duration} for permission={selected_permission}")
                    
            except Exception as e:
                print(f"[ERROR] Failed to update on permission change: {e}")
                import traceback
                traceback.print_exc()

        
        # Search modal action buttons
        @self.slack_app.action("refine_search_action")
        def action_refine_search(ack, body, client):
            ack()
            handle_refine_search_action(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("create_new_record_action")
        def action_create_new_record(ack, body, client):
            ack()
            from .handlers.modals import handle_create_new_record_action
            handle_create_new_record_action(body, client, self.config, self.keeper_client)
        
        @self.slack_app.action("self_destructive_checkbox")
        def action_self_destruct_checkbox(ack, body, client):
            """Handle self-destruct checkbox toggle to show/hide expiration field."""
            ack()
            
            try:
                # Get current checkbox state
                selected_options = body["actions"][0].get("selected_options", [])
                is_checked = len(selected_options) > 0

                # Get modal data
                view = body["view"]
                view_id = view["id"]
                metadata = json.loads(view["private_metadata"])
                
                # Rebuild modal with expiration field shown/hidden
                from .views import build_create_record_modal
                updated_modal = build_create_record_modal(
                    approval_data=metadata,
                    original_query="",
                    show_expiration=is_checked  # Show dropdown only if checked
                )
                
                # Update the modal
                client.views_update(
                    view_id=view_id,
                    view=updated_modal
                )

            except Exception as e:
                print(f"[ERROR] Error handling self-destruct checkbox: {e}")
                import traceback
                traceback.print_exc()
        
        # Modal submissions
        @self.slack_app.view("search_modal_submit")
        def view_search_submit(ack, body, client):
            # Pass ack to handler so it can show errors in modal
            try:
                handle_search_modal_submit(ack, body, client, self.config, self.keeper_client)
            except Exception as e:
                print(f"[ERROR] Error processing search modal submission: {e}")
                import traceback
                traceback.print_exc()
                # Acknowledge with error if handler failed
                try:
                    ack()
                except:
                    pass
        
        @self.slack_app.view("create_record_modal_submit")
        def view_create_record_submit(ack, body, client):
            ack()
            try:
                from .handlers.modals import handle_create_record_submit
                handle_create_record_submit(body, client, self.config, self.keeper_client)
            except Exception as e:
                print(f"[ERROR] Error creating record: {e}")
                import traceback
                traceback.print_exc()

    
    def start(self):
        """
        Start the Slack app in Socket Mode.
        """
        print("\n" + "="*60)
        print("Starting Keeper Commander Slack App")
        print("="*60)
        print("[OK] Socket Mode enabled")
        print("[INFO] Listening for Slack commands and interactions...")
        print("="*60 + "\n")
        
        # Check Keeper connectivity
        if self.keeper_client.health_check():
            print("[OK] Keeper Service Mode is accessible\n")
        else:
            print("[WARN] Warning: Cannot reach Keeper Service Mode")
            print(f"   URL: {self.config.keeper.service_url}")
            print("   The app will start but commands may fail.\n")
        
        # Start PEDM poller in background
        # try:
        #     self.pedm_poller.start()
        # except Exception as e:
        #     print(f"[WARN] Could not start PEDM poller: {e}")
        
        try:
            self.socket_handler.start()
        except KeyboardInterrupt:
            print("\n\n[INFO] Shutting down Keeper Slack App...")
            print("Goodbye!\n")


# Entry point for running directly
if __name__ == "__main__":
    app = KeeperSlackApp()
    app.start()

