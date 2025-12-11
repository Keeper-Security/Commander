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
Slack UI builders using Block Kit.
"""

import json
from typing import List, Dict, Any, Optional
from .models import RequestType, PermissionLevel, KeeperRecord, KeeperFolder
from .utils import format_timestamp, format_permission_name, format_duration, get_duration_options


def post_approval_request(
    client,
    approvals_channel: str,
    approval_id: str,
    requester_id: str,
    requester_name: str,
    identifier: str,
    is_uid: bool,
    request_type: RequestType,
    justification: str,
    duration: str = "24h",
    record_details = None,
    folder_details = None
):
    """
    Post approval request message to approvals channel.
    """
    if request_type == RequestType.RECORD:
        title = "Record Access Request"
        item_type = "Record"
    elif request_type == RequestType.FOLDER:
        title = "Folder Access Request"
        item_type = "Folder"
    elif request_type == RequestType.ONE_TIME_SHARE:
        title = "One-Time Share Request"
        item_type = "Record"
    
    # Build action data
    action_data = {
        "approval_id": approval_id,
        "requester_id": requester_id,
        "identifier": identifier,
        "is_uid": is_uid,
        "type": request_type.value,
        "justification": justification,
        "duration": duration
    }
    
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": title}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Requester:*\n<@{requester_id}>"},
                {"type": "mrkdwn", "text": f"*Request ID:*\n`{approval_id}`"},
                {"type": "mrkdwn", "text": f"*{item_type}:*\n`{identifier}`"},
                {"type": "mrkdwn", "text": f"*Format:*\n{'UID' if is_uid else 'Description'}"},
                {"type": "mrkdwn", "text": f"*Justification:*\n{justification}"},
                {"type": "mrkdwn", "text": f"*Requested:*\n{format_timestamp()}"}
            ]
        },
        {"type": "divider"}
    ]
    
    # Add fetched details section for UID requests
    if is_uid and (record_details or folder_details):
        if record_details:
            details_text = f"*Title:* {record_details.title}\n"
            details_text += f"*Type:* {record_details.record_type.replace('_', ' ').title()}\n"
            if record_details.notes:
                # Truncate notes to 200 chars
                notes_preview = record_details.notes[:200] + "..." if len(record_details.notes) > 200 else record_details.notes
                details_text += f"*Description:* {notes_preview}"
            else:
                details_text += f"*Description:* _No description_"
        elif folder_details:
            folder_type_display = folder_details.folder_type.replace('_', ' ').title()
            details_text = f"*Title:* {folder_details.name}\n"
            details_text += f"*Type:* {folder_type_display}"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{item_type} Details*\n\n{details_text}"
            }
        })
        blocks.append({"type": "divider"})
    
    # If description (not UID), add search button
    if not is_uid:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Action Required:* Approver must search for the correct {item_type.lower()}"
            },
            "accessory": {
                "type": "button",
                "text": {"type": "plain_text", "text": f"🔍 Search {item_type}s"},
                "action_id": f"search_{request_type.value}s",
                "value": json.dumps(action_data)
            }
        })
    else:
        # UID provided - add permission selector
        blocks.append(build_permission_selector_block(request_type))
    
        # Add duration selector for approver
        blocks.append({
            "type": "section",
            "block_id": "duration_selector",
            "text": {
                "type": "mrkdwn",
                "text": "*Grant Access For:*"
            },
            "accessory": {
                "type": "static_select",
                "action_id": "select_duration",
                "placeholder": {
                    "type": "plain_text",
                    "text": "Select duration"
                },
                "options": get_duration_options(),
                "initial_option": {
                    "text": {"type": "plain_text", "text": "24 hours"},
                    "value": "24h"
                }
            }
        })
    
    # Add approve/deny buttons based on request type
    if is_uid:
        # UID provided - show both Approve and Deny
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "approve_request",
                    "value": json.dumps(action_data)
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "action_id": "deny_request",
                    "value": json.dumps(action_data)
                }
            ]
        })
    else:
        # Description provided - only show Deny (must search to approve)
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny Request"},
                    "style": "danger",
                    "action_id": "deny_request",
                    "value": json.dumps(action_data)
                }
            ]
        })

    
    client.chat_postMessage(
        channel=approvals_channel,
        blocks=blocks,
        text=f"{title} from @{requester_name}"
    )

def build_permission_selector_block(request_type: RequestType, for_modal: bool = False) -> Dict[str, Any]:
    """
    Build permission level selector block.
    """
    if request_type == RequestType.ONE_TIME_SHARE:
        # One-time shares only support View Only and Can Edit
        options = [
            {
                "text": {"type": "plain_text", "text": "View Only"},
                "value": PermissionLevel.VIEW_ONLY.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Edit"},
                "value": PermissionLevel.CAN_EDIT.value
            }
        ]
        initial_option = options[0]  # "View Only" by default for one-time shares
    elif request_type == RequestType.RECORD:
        options = [
            {
                "text": {"type": "plain_text", "text": "View Only"},
                "value": PermissionLevel.VIEW_ONLY.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Edit"},
                "value": PermissionLevel.CAN_EDIT.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Share"},
                "value": PermissionLevel.CAN_SHARE.value
            },
            {
                "text": {"type": "plain_text", "text": "Edit and Share"},
                "value": PermissionLevel.EDIT_AND_SHARE.value
            },
            {
                "text": {"type": "plain_text", "text": "Change Owner"},
                "value": PermissionLevel.CHANGE_OWNER.value
            }
        ]
        initial_option = options[1]  # "Can Edit" by default
    else:  # FOLDER
        options = [
            {
                "text": {"type": "plain_text", "text": "No User Permissions"},
                "value": PermissionLevel.NO_PERMISSIONS.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Manage Users"},
                "value": PermissionLevel.MANAGE_USERS.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Manage Records"},
                "value": PermissionLevel.MANAGE_RECORDS.value
            },
            {
                "text": {"type": "plain_text", "text": "Can Manage Records and Users"},
                "value": PermissionLevel.MANAGE_ALL.value
            }
        ]
        initial_option = options[0]  # "No User Permissions" by default
    
    if for_modal:
        # Use input block for full-width dropdown (better display for long text in modals)
        return {
            "type": "input",
            "block_id": "permission_selector",
            "dispatch_action": True,  # Dispatch action immediately when selection changes
            "label": {
                "type": "plain_text",
                "text": "Select Permission Level"
            },
            "element": {
                "type": "static_select",
                "action_id": "select_permission",
                "placeholder": {"type": "plain_text", "text": "Choose permission level"},
                "initial_option": initial_option,
                "options": options
            }
        }
    else:
        # Use section block with accessory for messages (inline display)
        return {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Select Permission Level:*"},
            "accessory": {
                "type": "static_select",
                "action_id": "select_permission",
                "placeholder": {"type": "plain_text", "text": "Choose permission level"},
                "initial_option": initial_option,
                "options": options
            }
        }

def build_search_modal(
    query: str,
    search_type: str,
    results: List[Any],
    approval_data: Dict[str, Any],
    loading: bool = False,
    show_duration: bool = True
) -> Dict[str, Any]:
    """
    Build search results modal with interactive search.
    """
    # Determine request type from approval_data, fallback to search_type
    if 'type' in approval_data:
        try:
            request_type = RequestType(approval_data['type'])
        except (ValueError, KeyError):
            # Fallback if invalid type
            request_type = RequestType.RECORD if search_type == "record" else RequestType.FOLDER
    else:
        request_type = RequestType.RECORD if search_type == "record" else RequestType.FOLDER
    
    # Store search type and results in metadata for handler (needed early for action buttons and dynamic updates)
    metadata = approval_data.copy()
    metadata['search_type'] = search_type
    metadata['query'] = query
    
    # Cache results as serializable dicts (KeeperRecord/KeeperFolder objects can't be JSON serialized)
    if results:
        # Check if results are already dicts (from cached_results) or objects
        if isinstance(results[0], dict):
            # Already dicts, use as-is
            metadata['cached_results'] = results
        else:
            # Convert objects to dicts
            metadata['cached_results'] = [
                {
                    'uid': r.uid,
                    'title': r.title if hasattr(r, 'title') else r.name,
                    'record_type': r.record_type if hasattr(r, 'record_type') else getattr(r, 'folder_type', 'unknown'),
                    'notes': getattr(r, 'notes', '') or ''
                }
                for r in results
            ]
    else:
        metadata['cached_results'] = []
    
    blocks = [
        {
            "type": "input",
            "block_id": "search_query",
            "label": {"type": "plain_text", "text": "Search Term"},
            "element": {
                "type": "plain_text_input",
                "action_id": "update_search_query",
                "initial_value": query,
                "placeholder": {"type": "plain_text", "text": "Type your search query..."}
            },
            "hint": {
                "type": "plain_text",
                "text": "Modify the search term and click the Refine button below"
            }
        }
    ]
    
    # Build action buttons (Refine Search + optionally Create New Record)
    action_buttons = [
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "🔍 Refine Search"},
            "action_id": "refine_search_action",
            "value": json.dumps(metadata)
        }
    ]
    
    # Add "Create New Record" button beside Refine (only for description-based RECORD requests)
    if (search_type == "record" and 
        approval_data.get('request_type') not in ['one_time_share'] and
        not approval_data.get('is_uid', False)):
        action_buttons.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "Create New Record"},
            "style": "primary",
            "action_id": "create_new_record_action",
            "value": json.dumps(metadata)
        })
    
    # Add the combined action block
    blocks.append({
        "type": "actions",
        "elements": action_buttons
    })
    
    # Add helpful context if Create button is shown
    if len(action_buttons) > 1:
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": "_Or create a new record and share it_"
            }]
        })
    
    blocks.extend([
        {
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"_{'Searching...' if loading else f'Showing {len(results)} result(s) for: `{query}`'}_"
            }]
        },
        {"type": "divider"}
    ])
    
    if results:
        # Add radio button selector for results
        options = []
        initial_option = None  # Will be set if newly_created_uid matches
        newly_created_uid = approval_data.get('newly_created_uid')
        
        for item in results[:10]:  # Limit to 10 for UX
            # Handle both objects (KeeperRecord/KeeperFolder) and dicts (cached results)
            if isinstance(item, dict):
                # Cached result dict
                text = f"{item.get('title', 'Untitled')} ({item.get('uid', '')})"
                value = item.get('uid', '')
            elif isinstance(item, KeeperRecord):
                text = f"{item.title} ({item.uid})"
                value = item.uid
            else:  # KeeperFolder
                text = f"{item.name} ({item.uid})"
                value = item.uid
            
            option = {
                "text": {"type": "plain_text", "text": text},
                "value": value
            }
            options.append(option)
            
            # Pre-select if this is the newly created record
            if newly_created_uid and value == newly_created_uid:
                initial_option = option
        
        # If we have a newly created record, add context message
        if initial_option:
            blocks.insert(-1, {  # Insert before the last divider
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"New record '{approval_data.get('newly_created_title', '')}' created"
                }]
            })
        
        radio_block = {
            "type": "input",
            "block_id": "selected_item",
            "label": {"type": "plain_text", "text": f"Select {search_type}:"},
            "element": {
                "type": "radio_buttons",
                "action_id": "item_selection",
                "options": options
            },
            "optional": False  # Make selection required
        }
        
        # Add initial_option if we have a newly created record
        if initial_option:
            radio_block["element"]["initial_option"] = initial_option
            print(f"[DEBUG] Pre-selecting newly created record: {newly_created_uid}")
        else:
            print(f"[DEBUG] No pre-selection - newly_created_uid: {newly_created_uid}")
        
        blocks.append(radio_block)
        
        # Only show permission and duration selectors if NOT creating self-destruct link
        if not approval_data.get('create_self_destruct', False):
            # Add permission selector (full-width for modal)
            blocks.append(build_permission_selector_block(request_type, for_modal=True))
            
            # Add duration selector (conditionally based on permission)
            if show_duration:
                blocks.append({
                    "type": "input",
                    "block_id": "grant_duration",
                    "label": {"type": "plain_text", "text": "Grant Access For"},
                    "optional": True,
                    "element": {
                        "type": "static_select",
                        "action_id": "grant_duration_select",
                        "options": get_duration_options(),
                        "initial_option": {
                            "text": {"type": "plain_text", "text": "24 hours"},
                            "value": "24h"
                        }
                    },
                    "hint": {
                        "type": "plain_text",
                        "text": "Select how long the access should remain active"
                    }
                })
            else:
                # Show permanent access notice
                blocks.append({
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": "ℹ️ *Permanent Access:* The selected permission does not support time limits."
                    }]
                })
        else:
            # Self-destruct mode - show info message instead
            duration_text = approval_data.get('self_destruct_duration', 'N/A')
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Self-Destruct Record Settings*\n\nRecord will be shared directly to requester's vault\nAuto-deletes after: *{duration_text}*\nAccess: View-Only"
                }
            })
        
        if len(results) > 10:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"_Showing 10 of {len(results)} results_"
                }]
            })
    else:
        # Show loading or no results message
        if loading:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":hourglass_flowing_sand: *Searching...*\n\nFetching {search_type}s matching `{query}` from Keeper vault..."
                }
            })
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": "_This may take a few seconds. The modal will update automatically when results are ready._"
                }]
            })
        else:
            message_text = f"No {search_type}s found matching `{query}`\n\n_Try modifying your search above and click 'Refine Search' to see updated results_"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message_text
                }
            })
    
    # Modal configuration
    modal_config = {
        "type": "modal",
        "callback_id": "search_modal_submit",
        "private_metadata": json.dumps(metadata),
        "title": {"type": "plain_text", "text": f"🔍 Search {search_type.capitalize()}s"},
        # No close button - users can press ESC to dismiss
        "blocks": blocks
    }

    # Submit button is required by Slack when modal has input blocks
    if results:
        # Change button text based on mode
        if approval_data.get('create_self_destruct', False):
            modal_config["submit"] = {"type": "plain_text", "text": "Share Record"}
        else:
            modal_config["submit"] = {"type": "plain_text", "text": "Approve Access"}
    else:
        # When no results, submit performs search
        modal_config["submit"] = {"type": "plain_text", "text": "🔍 Search"}
    
    return modal_config

def build_create_record_modal(approval_data: Dict[str, Any], original_query: str = "", show_expiration: bool = False) -> Dict[str, Any]:
    """
    Build modal for creating a new record.
    After creation, will return to search modal with new record pre-selected.
    """
    blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Creating record for:* <@{approval_data.get('requester_id')}>\n_After creation, you'll be able to review and approve sharing_"
                }
            },
            {"type": "divider"},
            {
                "type": "input",
                "block_id": "record_type",
                "label": {"type": "plain_text", "text": "Record Type"},
                "element": {
                    "type": "static_select",
                    "action_id": "type_select",
                    "placeholder": {"type": "plain_text", "text": "Select record type"},
                    "initial_option": {
                        "text": {"type": "plain_text", "text": "Login"},
                        "value": "login"
                    },
                    "options": [
                        {
                            "text": {"type": "plain_text", "text": "Login"},
                            "value": "login"
                        }
                    ]
                }
            },
            {
                "type": "input",
                "block_id": "record_title",
                "label": {"type": "plain_text", "text": "Title (Required)"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "title_input",
                    "initial_value": original_query,
                    "placeholder": {"type": "plain_text", "text": "e.g., Production Database"}
                }
            },
            {
                "type": "input",
                "block_id": "record_login",
                "label": {"type": "plain_text", "text": "Login / Username (Required)"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "login_input",
                    "placeholder": {"type": "plain_text", "text": "e.g., admin@company.com"}
                }
            },
            {
                "type": "input",
                "block_id": "record_password",
                "label": {"type": "plain_text", "text": "Password (Required)"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "password_input",
                    "placeholder": {"type": "plain_text", "text": "Enter $GEN to auto-generate or provide your own"}
                },
            },
            {
                "type": "input",
                "block_id": "record_url",
                "label": {"type": "plain_text", "text": "Website Address"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "url_input",
                    "placeholder": {"type": "plain_text", "text": "e.g., https://app.example.com"}
                },
                "optional": True
            },
            {
                "type": "input",
                "block_id": "record_notes",
                "label": {"type": "plain_text", "text": "Notes"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "notes_input",
                    "multiline": True,
                    "placeholder": {"type": "plain_text", "text": "Additional information about this record"}
                },
                "optional": True
            },
            {"type": "divider"}
    ]
    
    checkbox_block = {
        "type": "actions",
        "block_id": "self_destructive_actions",
        "elements": [
            {
                "type": "checkboxes",
                "action_id": "self_destructive_checkbox",
                "options": [
                    {
                        "text": {"type": "plain_text", "text": "Enable self-destruct (optional)"},
                        "value": "enabled"
                    }
                ]
            }
        ]
    }
    
    # Pre-check the checkbox if expiration dropdown should be shown
    if show_expiration:
        checkbox_block["elements"][0]["initial_options"] = [
            {
                "text": {"type": "plain_text", "text": "Enable self-destruct (optional)"},
                "value": "enabled"
            }
        ]
    
    blocks.append(checkbox_block)
    
    # Conditionally add expiration dropdown only if checkbox is checked
    if show_expiration:
        blocks.append({
            "type": "input",
            "block_id": "link_expiration",
            "label": {"type": "plain_text", "text": "Link Expires In"},
            "element": {
                "type": "static_select",
                "action_id": "expiration_select",
                "placeholder": {"type": "plain_text", "text": "Select expiration time"},
                "initial_option": {
                    "text": {"type": "plain_text", "text": "24 hours"},
                    "value": "24h"
                },
                "options": [
                    {
                        "text": {"type": "plain_text", "text": "1 hour"},
                        "value": "1h"
                    },
                    {
                        "text": {"type": "plain_text", "text": "24 hours"},
                        "value": "24h"
                    },
                    {
                        "text": {"type": "plain_text", "text": "1 week"},
                        "value": "7d"
                    },
                    {
                        "text": {"type": "plain_text", "text": "30 days"},
                        "value": "30d"
                    },
                    {
                        "text": {"type": "plain_text", "text": "90 days"},
                        "value": "90d"
                    }
                ]
            }
        })
    
    return {
        "type": "modal",
        "callback_id": "create_record_modal_submit",
        "private_metadata": json.dumps(approval_data),
        "title": {"type": "plain_text", "text": "Create New Record"},
        "submit": {"type": "plain_text", "text": "Create Record"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks
    }

def update_approval_message(
    client,
    channel_id: str,
    message_ts: str,
    status: str,
    original_blocks: List[Dict]
):
    """
    Update approval message with status.
    """
    # Remove action buttons
    updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
    
    # Add status section
    updated_blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Status:* {status}\n*Updated:* {format_timestamp()}"
        }
    })
    
    client.chat_update(
        channel=channel_id,
        ts=message_ts,
        text=status,  # Fallback text for notifications and accessibility
        blocks=updated_blocks
    )

def send_access_granted_dm(
    client,
    user_id: str,
    approval_id: str,
    item_type: str,
    item_title: str,
    share_url: str,
    expires_at: str
):
    """Send DM to requester when access is granted."""
    try:
        dm_response = client.conversations_open(users=[user_id])
        dm_channel_id = dm_response["channel"]["id"]
        
        # Build access info message
        if share_url and share_url != 'N/A':
            access_info = f"Access URL: {share_url}"
        else:
            access_info = "Access Type: Direct vault access (check your Keeper vault)"

        client.chat_postMessage(
            channel=dm_channel_id,
            text=f"*Access Granted!*\n\n"
                 f"Request ID: `{approval_id}`\n"
                 f"{item_type.capitalize()}: *{item_title}*\n"
                 f"{access_info}\n"
                 f"Expires: {expires_at}\n\n"
        )
    except Exception as e:
        print(f"Error sending DM to {user_id}: {e}")

def send_access_denied_dm(
    client,
    user_id: str,
    approval_id: str,
    item_type: str,
    approver_name: str
):
    """Send DM to requester when access is denied."""
    client.chat_postMessage(
        channel=user_id,
        text=f"*Access Request Denied*\n\n"
             f"Request ID: `{approval_id}`\n"
             f"{item_type.capitalize()} access request was denied by {approver_name}.\n\n"
             f"If you believe this was in error, please contact your manager or the security team."
    )

def send_share_link_dm(
    client,
    user_id: str,
    record_uid: str,
    share_url: str,
    record_title: str = None,
    expires_at: str = None,
    approval_id: str = None
):
    """
    Send one-time share link via DM.
    """
    # Build message
    message = f"*One-Time Share Link Created*\n\n"
    
    if record_title:
        message += f"*Record:* {record_title}\n"
    message += f"*UID:* `{record_uid}`\n"
    
    if approval_id:
        message += f"*Request ID:* `{approval_id}`\n"
    
    message += f"\n*Share Link:*\n{share_url}\n\n"
    
    if expires_at:
        message += f"*Expires:* {expires_at}\n\n"
    message += "*Security Notice:*\n"
    message += "• This link can only be opened on ONE device\n"
    message += "• It expires after first access or time limit\n"
    message += "• Share only via secure channels (email, SMS, etc.)\n"
    message += "• Do NOT post in public Slack channels\n"
    message += "• Keep this link confidential"
    
    try:
        dm_response = client.conversations_open(users=[user_id])
        dm_channel = dm_response["channel"]["id"]
        
        client.chat_postMessage(
            channel=dm_channel,
            text=message
        )
    except Exception as e:
        print(f"Error sending share link DM: {e}")

def format_timestamp(timestamp_str: Optional[str] = None) -> str:
    """
    Format ISO timestamp for display.
    """
    from datetime import datetime
    
    if timestamp_str is None:
        # No timestamp provided, use current time
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return timestamp_str

def post_pedm_approval_request(
    client,
    approvals_channel: str,
    request_data: dict
):
    """
    Post PEDM approval request to Slack channel.
    """
    from .models import PEDMRequest
    from datetime import datetime, timedelta
    
    # Parse request data
    try:
        request = PEDMRequest.from_dict(request_data)
    except Exception as e:
        print(f"[ERROR] Failed to parse PEDM request: {e}")
        return
    
    # Calculate expiration
    try:
        created_dt = datetime.fromisoformat(request.created.replace('Z', '+00:00'))
        expires_dt = created_dt + timedelta(minutes=request.expire_in)
        expires_str = expires_dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"[WARN] Could not parse expiration time: {e}")
        expires_str = f"{request.expire_in} minutes from creation"
    
    # Build approval card
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "PEDM Approval Request"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*User:*\n{request.username}"},
                {"type": "mrkdwn", "text": f"*Request ID:*\n`{request.approval_uid}`"},
                {"type": "mrkdwn", "text": f"*Type:*\n{request.approval_type}"},
                {"type": "mrkdwn", "text": f"*Expires:*\n{expires_str}"},
                {"type": "mrkdwn", "text": f"*Created:*\n{format_timestamp(request.created)}"},
                {"type": "mrkdwn", "text": f"*Agent UID:*\n`{request.agent_uid}`"}
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Command Details*\n\n"
                        f"*Executable:* `{request.file_name}`\n"
                        f"*Path:* `{request.file_path}`\n"
                        f"*Command:* `{request.command}`\n"
                        f"*Description:* {request.description}"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Justification:*\n{request.justification or '_No justification provided_'}"
            }
        },
        {"type": "divider"},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "approve_pedm_request",
                    "value": request.approval_uid
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "action_id": "deny_pedm_request",
                    "value": request.approval_uid
                }
            ]
        }
    ]
    
    try:
        client.chat_postMessage(
            channel=approvals_channel,
            blocks=blocks,
            text=f"PEDM Approval Request from {request.username}"
        )
        print(f"[OK] Posted PEDM request {request.approval_uid} to Slack")
    except Exception as e:
        print(f"[ERROR] Failed to post PEDM request to Slack: {e}")
