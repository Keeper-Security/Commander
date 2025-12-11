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

"""Handlers for modal dialog submissions."""

import json
from typing import Dict, Any
from ..models import PermissionLevel
from ..views import update_approval_message, send_access_granted_dm
from ..utils import parse_duration_to_seconds, format_duration, get_user_email_from_slack


def handle_search_modal_submit(ack, body: Dict[str, Any], client, config, keeper_client):
    """
    Handle search modal submission.
    Can either re-search with new query or approve with selected item.
    """
    # Extract approval data from private metadata
    approval_data = json.loads(body["view"]["private_metadata"])
    
    # Extract values from form
    values = body["view"]["state"]["values"]
    
    # Check if user modified search query
    new_query = values.get("search_query", {}).get("update_search_query", {}).get("value", "").strip()
    search_type = approval_data.get("search_type", approval_data.get("type", "record"))
    
    print(f"[DEBUG] Modal submit - new_query: '{new_query}', search_type: {search_type}")
    
    # Check if radio buttons block exists (means we have results)
    selected_item_block = values.get("selected_item")
    has_results = selected_item_block is not None
    
    print(f"[DEBUG] Has results block: {has_results}")
    
    if not has_results:
        # No results yet - user is searching
        print(f"[DEBUG] No results block - running search with query: '{new_query}'")
        
        # Acknowledge immediately for search operations
        ack()
        
        # Run search
        if search_type == "record":
            results = keeper_client.search_records(new_query, limit=20)
        else:
            results = keeper_client.search_folders(new_query, limit=20)
        
        # Rebuild and update modal with results using API call
        from ..views import build_search_modal
        updated_modal = build_search_modal(
            query=new_query,
            search_type=search_type,
            results=results,
            approval_data=approval_data
        )
        
        print(f"[DEBUG] Updating modal with {len(results)} results")
        
        try:
            client.views_update(
                view_id=body["view"]["id"],
                view=updated_modal
            )
            print(f"[DEBUG] Modal updated successfully")
        except Exception as e:
            print(f"[ERROR] Failed to update modal: {e}")
        
        return  # Done with search update

    selected_item = selected_item_block.get("item_selection", {}).get("selected_option")
    print(f"[DEBUG] Selected item: {selected_item}")
    
    # If no item selected, show error in modal
    if not selected_item:
        print(f"[WARN] No item selected - user submitted without selecting")
        ack(response_action="update", view={
            "type": "modal",
            "title": {"type": "plain_text", "text": "❌ Selection Required"},
            "close": {"type": "plain_text", "text": "Close"},
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Please select an item before approving.*\n\nGo back and select a record/folder from the list."
                    }
                }
            ]
        })
        return
    
    # Item selected - acknowledge IMMEDIATELY (Slack requires ack within 3 seconds)
    # This closes the modal; errors will be shown in a new modal
    ack()
    
    selected_uid = selected_item["value"]
    
    # Get record title from the selected item or metadata
    record_title = selected_item.get("text", {}).get("text", "").split(" (")[0] if selected_item else f"Record {selected_uid}"
    if not record_title or record_title.startswith("Record "):
        record_title = approval_data.get('newly_created_title', approval_data.get('record_title', f"Record {selected_uid}"))
    
    # Check if this is a self-destruct record
    is_self_destruct = approval_data.get('create_self_destruct', False)
    
    # Extract permission and duration
    if is_self_destruct:
        # Self-destruct records: use duration from creation, always view-only
        print(f"[INFO] Self-destruct record detected - sharing with view-only access")
        permission = PermissionLevel.VIEW_ONLY
        self_destruct_duration_str = approval_data.get('self_destruct_duration', '24h')
        duration_seconds = parse_duration_to_seconds(self_destruct_duration_str)
        duration_value = self_destruct_duration_str
        duration_text = format_duration(self_destruct_duration_str)
        editable = False
    else:
        # Normal records: use admin-selected permission and duration
        permission_block = values.get("permission_selector", {}).get("select_permission", {})
        permission_value = permission_block.get("selected_option", {}).get("value", "view_only")
        permission = PermissionLevel(permission_value)
        
        # For one-time shares, convert permission to editable flag
        editable = (permission_value == PermissionLevel.CAN_EDIT.value)
        
        # Some permissions are always permanent (no duration)
        PERMANENT_ONLY_PERMISSIONS = [
            # Record permissions (permanent)
            PermissionLevel.CAN_SHARE.value,
            PermissionLevel.EDIT_AND_SHARE.value,
            PermissionLevel.CHANGE_OWNER.value,
            # Folder permissions (permanent)
            PermissionLevel.MANAGE_USERS.value,
            PermissionLevel.MANAGE_ALL.value
        ]
        
        if permission_value in PERMANENT_ONLY_PERMISSIONS:
            # Force permanent access for these permissions
            duration_seconds = None
            duration_value = "permanent"
            duration_text = "Permanent"
            print(f"[INFO] {permission_value} is permanent-only, ignoring duration selector")
        else:
            # Normal duration handling for View Only and Can Edit
            duration_block = values.get("grant_duration", {}).get("grant_duration_select", {})
            duration_value = duration_block.get("selected_option", {}).get("value", "24h")
            duration_seconds = parse_duration_to_seconds(duration_value)
            duration_text = format_duration(duration_value)
    
    # Get approver info
    approver_id = body["user"]["id"]
    approver_name = body["user"]["name"]
    
    # Grant access
    requester_id = approval_data["requester_id"]
    request_type = approval_data["type"]
    approval_id = approval_data["approval_id"]
    
    # Get user's real email from Slack
    user_email = get_user_email_from_slack(client, requester_id)
    
    try:
        if request_type == "record":
            result = keeper_client.grant_record_access(
                record_uid=selected_uid,
                user_email=user_email,
                permission=permission,
                duration_seconds=duration_seconds
            )
        elif request_type == "folder":
            result = keeper_client.grant_folder_access(
                folder_uid=selected_uid,
                user_email=user_email,
                permission=permission,
                duration_seconds=duration_seconds
            )
        elif request_type == "one_time_share":
            # Create one-time share link with editable permission
            result = keeper_client.create_one_time_share(
                record_uid=selected_uid,
                duration_seconds=duration_seconds,
                editable=editable
            )
        else:
            result = {'success': False, 'error': f'Unknown request type: {request_type}'}
        
        if result.get('success'):
            # Modal already closed via early ack()
            from ..views import send_share_link_dm
            
            # Send appropriate DM based on request type
            if request_type == "one_time_share":
                # Send one-time share link
                send_share_link_dm(
                client=client,
                user_id=requester_id,
                    record_uid=selected_uid,
                    share_url=result.get('share_url'),
                    record_title=record_title,
                    expires_at=result.get('expires_at'),
                    approval_id=approval_id
                )
                print(f"Approval {approval_id}: Created one-time share via search modal by {approver_id}")
            else:
                # Notify requester with access granted (works for both regular and self-destruct records)
                # Build message with self-destruct note if applicable
                access_message = f"*Access Granted!*\n\n" \
                                f"*Request ID:* `{approval_id}`\n" \
                                f"*Record:* {record_title}\n" \
                                f"*UID:* `{selected_uid}`\n" \
                                f"*Access Type:* Direct vault access\n" \
                                f"*Permission:* {permission.value}\n" \
                                f"*Expires:* {result.get('expires_at', duration_text)}"
                
                # Add self-destruct notice if applicable
                if is_self_destruct:
                    access_message += f"\n\n⚠️ *Self-Destruct Record*\n" \
                                    f"This record will automatically delete from the vault after {duration_text}."
                
                from ..utils import send_dm
                send_dm(client, requester_id, access_message)
                print(f"Approval {approval_id}: Granted via search modal by {approver_id}" + 
                      (" (self-destruct)" if is_self_destruct else ""))
            
            # Update original approval card to show approved status
            message_ts = approval_data.get("message_ts")
            channel_id = approval_data.get("channel_id", config.slack.approvals_channel_id)
            
            if message_ts:
                try:
                    from datetime import datetime
                    
                    # Get expiration info from result
                    expires_at = result.get('expires_at', 'Never')
                    is_permanent = duration_value == "permanent"
                    
                    # Create status message based on request type
                    if request_type == "one_time_share":
                        status_msg = f"*One-Time Share Link Created*\nLink sent to requester • Expires: {expires_at}"
                        approval_text = "One-Time Share Request Approved"
                    else:
                        if is_permanent:
                            status_msg = "*Permanent Access Granted*\nNo expiration - Access remains active indefinitely"
                        else:
                            status_msg = f"*Temporary Access Granted*\nAccess will expire on *{expires_at}*"
                        
                        # Add self-destruct note if applicable
                        if is_self_destruct:
                            status_msg += f"\n\n⚠️ *Self-Destruct Record*\nRecord will auto-delete after {duration_text}"
                            approval_text = "Self-Destruct Record Access Approved"
                        else:
                            approval_text = "Access Request Approved"
                    
                    client.chat_update(
                        channel=channel_id,
                        ts=message_ts,
                        text=f"Request approved by <@{approver_id}>",
                        blocks=[
                            {
                                "type": "header",
                                "text": {
                                    "type": "plain_text",
                                    "text": approval_text,
                                    "emoji": True
                                }
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"*Record:* `{selected_uid}`\n"
                                            f"*Requester:* <@{requester_id}>\n"
                                            f"*Approved by:* <@{approver_id}>"
                                }
                            },
                            {
                                "type": "divider"
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": status_msg
                                }
                            },
                            {
                                "type": "context",
                                "elements": [
                                    {
                                        "type": "mrkdwn",
                                        "text": f"Access granted via search • {datetime.now().strftime('%B %d, %Y at %I:%M %p')}"
                                    }
                                ]
                            }
                        ]
                    )
                    print(f"[INFO] Updated approval card {approval_id} (message_ts: {message_ts})")
                except Exception as update_error:
                    print(f"[ERROR] Failed to update approval card: {update_error}")
            else:
                print(f"[WARN] No message_ts found in approval_data, cannot update card")
            
            # Modal closed via early ack - success!
            print(f"[INFO] Access granted successfully for {approval_id}")
        else:
            # Failed to grant access - show error in a NEW modal
            error_msg = result.get('error', 'Unknown error')
            print(f"[ERROR] Failed to grant access: {error_msg}")
            
            # Open a new modal to show the error (original modal already closed)
            try:
                client.views_open(
                    trigger_id=body.get("trigger_id"),
                    view={
                        "type": "modal",
                        "title": {"type": "plain_text", "text": "❌ Error"},
                        "close": {"type": "plain_text", "text": "Close"},
                        "blocks": [
                            {
                                "type": "header",
                                "text": {"type": "plain_text", "text": "Failed to Grant Access"}
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": error_msg
                                }
                            },
                            {"type": "divider"},
                            {
                                "type": "context",
                                "elements": [{
                                    "type": "mrkdwn",
                                    "text": "Please try again with different settings, or contact support."
                                }]
                            }
                        ]
                    }
                )
            except Exception as modal_error:
                # If we can't open a modal (trigger_id expired), send DM instead
                print(f"[WARN] Could not open error modal: {modal_error}")
                from ..utils import send_error_dm
                send_error_dm(client, approver_id, "Failed to Grant Access", error_msg)
            
    except Exception as e:
        print(f"[ERROR] Error granting access from search modal: {e}")
        import traceback
        traceback.print_exc()
        
        # Try to show error - send DM as fallback since ack may have been called
        from ..utils import send_error_dm
        send_error_dm(
            client, body["user"]["id"],
            "System Error",
            f"An error occurred while processing your approval: {str(e)}"
        )


def handle_refine_search_action(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle 'Refine Search' button click in search modal.
    Re-runs search with the updated query from the search field.
    """
    # Extract view data
    view = body["view"]
    values = view["state"]["values"]
    approval_data = json.loads(view["private_metadata"])
    
    # Get updated search query
    new_query = values.get("search_query", {}).get("update_search_query", {}).get("value", "").strip()
    search_type = approval_data.get("search_type", "record")
    
    print(f"[DEBUG] Refining search with query: '{new_query}'")
    
    # Re-run search
    if search_type == "record":
        results = keeper_client.search_records(new_query, limit=20)
    else:
        results = keeper_client.search_folders(new_query, limit=20)
    
    # Build updated modal
    from ..views import build_search_modal
    updated_modal = build_search_modal(
        query=new_query,
        search_type=search_type,
        results=results,
        approval_data=approval_data
    )
    
    print(f"[DEBUG] Updating modal with {len(results)} results")
    
    # Update the modal
    try:
        client.views_update(
            view_id=view["id"],
            view=updated_modal
        )
    except Exception as e:
        print(f"Error updating search modal: {e}")


def handle_create_new_record_action(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle 'Create New Record' button click in search modal.
    Opens a modal for creating a new record.
    """
    from ..views import build_create_record_modal
    
    # Extract metadata from button value
    value = body["actions"][0].get("value", "{}")
    approval_data = json.loads(value)
    
    # Get the current search query from the view state
    view_state = body.get("view", {}).get("state", {}).get("values", {})
    current_query = view_state.get("search_query", {}).get("update_search_query", {}).get("value", "")
    
    try:
        # Open the create record modal (stacked on top) - initially without expiration dropdown
        client.views_push(
            trigger_id=body["trigger_id"],
            view=build_create_record_modal(approval_data, current_query, show_expiration=False)
        )
    except Exception as e:
        print(f"[ERROR] Failed to open create record modal: {e}")


def handle_create_record_submit(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle create record modal submission.
    Creates the record, then returns to search modal with new record pre-selected.
    """
    # Extract approval metadata
    metadata = json.loads(body["view"]["private_metadata"])
    requester_id = metadata.get('requester_id')
    search_type = metadata.get('search_type', 'record')
    
    # IMMEDIATELY show loading state on previous view (before any slow operations)
    view_id = body["view"].get("previous_view_id")
    if view_id:
        try:
            from ..views import build_search_modal
            loading_modal = build_search_modal(
                query="Creating record...",
                search_type=search_type,
                results=[],
                approval_data=metadata,
                loading=True  # Show loading state
            )
            update_response = client.views_update(
                view_id=view_id,
                view=loading_modal
            )
            # Get the updated view_id from the response
            if update_response.get('ok'):
                view_id = update_response['view']['id']
                print(f"[DEBUG] Loading state shown, updated view_id: {view_id}")
            else:
                print(f"[WARN] Loading state update returned ok=False")
        except Exception as e:
            print(f"[ERROR] Failed to show initial loading state: {e}")
            view_id = None  # Clear view_id if loading update failed
    
    # Extract form values
    values = body["view"]["state"]["values"]
    
    title = (values.get("record_title", {}).get("title_input", {}).get("value") or "").strip()
    login = (values.get("record_login", {}).get("login_input", {}).get("value") or "").strip()
    password = (values.get("record_password", {}).get("password_input", {}).get("value") or "").strip()
    url = (values.get("record_url", {}).get("url_input", {}).get("value") or "").strip()
    notes = (values.get("record_notes", {}).get("notes_input", {}).get("value") or "").strip()
    
    # Extract self-destruct checkbox and expiration
    self_destruct_enabled = False
    self_destruct_duration = None
    
    # Check if checkbox is checked (from actions block)
    checkbox_options = values.get("self_destructive_actions", {}).get("self_destructive_checkbox", {}).get("selected_options", [])
    if checkbox_options and len(checkbox_options) > 0:
        self_destruct_enabled = True
        
        # Get expiration duration (from input block)
        expiration_value = values.get("link_expiration", {}).get("expiration_select", {}).get("selected_option", {}).get("value")
        if expiration_value:
            self_destruct_duration = expiration_value  # e.g., "1h", "24h", "7d", etc.
        
        # Mark in metadata that self-destruct is being used
        metadata['create_self_destruct'] = True
        metadata['self_destruct_duration'] = self_destruct_duration
    
    if not title:
        # Return error to modal
        return {
            "response_action": "errors",
            "errors": {
                "record_title": "Title is required"
            }
        }
    
    try:
        # Create the record
        print(f"[INFO] Creating record '{title}' for requester {requester_id}" + (f" with self-destruct" if self_destruct_enabled else ""))
        generate_password = not password
        
        create_result = keeper_client.create_record(
            title=title,
            login=login or None,
            password=password or None,
            url=url or None,
            notes=notes or None,
            generate_password=generate_password,
            self_destruct_duration=self_destruct_duration if self_destruct_enabled else None
        )
        
        if not create_result.get('success'):
            # Show error in modal
            error_msg = create_result.get('error', 'Unknown error')
            # Send DM with error since we can't easily show it in modal after ack
            from ..utils import send_error_dm
            user_id = body["user"]["id"]
            send_error_dm(
                client, user_id,
                "Failed to create record",
                error_msg
            )
            return
        
        record_uid = create_result.get('record_uid')
        is_self_destruct = create_result.get('self_destruct', False)
        
        if not record_uid:
            print("[WARN] Record created but UID not found")
            return
        
        print(f"[OK] Record created: {record_uid}" + (" (self-destruct)" if is_self_destruct else ""))
        print(f"[DEBUG] view_id from body: {view_id}")
        
        # Return to search modal with new record pre-selected (works for both regular and self-destruct)
        # Skip search - we already have all the data we need from record creation!
        print(f"[DEBUG] Creating result object for newly created record: '{title}' ({record_uid})")
        
        from ..models import KeeperRecord
        newly_created_record = KeeperRecord(
            uid=record_uid,
                title=title,
            record_type='login',
            notes=notes or None
        )
        
        # Show only the newly created record (no unnecessary search)
        search_results = [newly_created_record]
        print(f"[DEBUG] Optimized: Showing newly created record without search")
        
        # Build updated search modal with results, pre-selecting the new record
        from ..views import build_search_modal
        
        # Add the newly created UID to metadata so we can pre-select it
        metadata['newly_created_uid'] = record_uid
        metadata['newly_created_title'] = title
        
        print(f"[DEBUG] Building search modal with query='{title}', results={len(search_results)}")
        updated_modal = build_search_modal(
            query=title,
            search_type=search_type,
            results=search_results,
            approval_data=metadata,
            loading=False
        )
        
        # Use the view_id we already retrieved
        if not view_id:
            print("[ERROR] No previous_view_id found, cannot update search modal")
            # Send DM instead
            from ..utils import send_success_dm
            user_id = body["user"]["id"]
            send_success_dm(
                client, user_id,
                "Record Created",
                f"*Title:* {title}\n"
                f"*UID:* `{record_uid}`\n\n"
                f"Please use the search modal to find and approve access for <@{requester_id}>."
            )
            return
        
        # Update the search modal (pop back to it with updated content)
        print(f"[DEBUG] Attempting to update view_id: {view_id}")
        try:
            response = client.views_update(
                view_id=view_id,
                view=updated_modal
            )
            print(f"[OK] Search modal updated successfully with query '{title}'")
            print(f"[DEBUG] View update response: {response.get('ok', False)}")
        except Exception as e:
            print(f"[ERROR] Failed to update search modal: {e}")
            import traceback
            traceback.print_exc()
            # Fallback: send DM with instructions
            from ..utils import send_success_dm
            user_id = body["user"]["id"]
            send_success_dm(
                client, user_id,
                "Record Created",
                f"*Title:* {title}\n"
                f"*UID:* `{record_uid}`\n\n"
                f"Please search for this record and approve access for <@{requester_id}>."
            )
        
    except Exception as e:
        print(f"[ERROR] Error in create record flow: {e}")
        import traceback
        traceback.print_exc()
        
        # Send error DM
        from ..utils import send_error_dm
        user_id = body["user"]["id"]
        send_error_dm(
            client, user_id,
            "Error creating record",
            str(e)
        )

