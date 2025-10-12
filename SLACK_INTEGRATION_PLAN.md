# Slack Commander Integration Plan

## Overview

Integrate Slack approval workflow functionality directly into the existing Commander Service Mode Flask application. Users will be able to request access to Keeper record UIDs through Slack, with designated approvers managing requests through interactive Slack messages.

## Architecture Integration

- **Extend existing Flask app**: Add new Slack blueprint to the current Commander Service Mode architecture
- **Leverage existing command system**: Use `CommandExecutor.execute()` for record sharing via `share-record` commands
- **Service-based configuration**: Configure through `service-create` command (not environment variables)
- **In-memory request tracking**: Simple Python dict-based storage for approval workflow state

## Key Components

### 1. Slack API Blueprint (`/keepercommander/service/api/slack.py`)

New Flask blueprint with endpoints:

- `/api/slack/events` - Handle Slack Events API (mentions, messages)
- `/api/slack/interactive` - Handle interactive component responses (approve/deny buttons)
- `/api/slack/status` - Check Slack integration status

### 2. Slack Integration Service (`/keepercommander/service/slack/`)

- **`slack_client.py`** - Slack Web API client wrapper
- **`approval_manager.py`** - Core approval workflow logic and in-memory storage
- **`message_builder.py`** - Slack message formatting and interactive components
- **`config.py`** - Service configuration management
- **`scheduled_tasks.py`** - Background thread for access expiration and cleanup

### 3. Configuration Integration

- **Interactive Setup**: Added to `service-create` command prompts
- **CLI Parameters**: New flags for streamlined configuration
- **Service Config**: Stored in service configuration file with vault backup

## Implementation Flow

### Request Flow:

1. User mentions bot in Slack: `@keeper-bot request access <record_uid> for 30m`
2. Bot parses request, validates record UID exists
3. Posts approval request to designated channel with approve/deny buttons
4. Stores request in in-memory tracker with expiration

### Approval Flow:

1. Approver clicks approve/deny button
2. Track approvals (configurable threshold, defaults to 1 approval required, any denial cancels)
3. On sufficient approvals: Execute `share-record -e user@company.com --expire-in 30m <record_uid>` 
4. Send private message to requester with vault link
5. Schedule background task for access cleanup

### Expiration Flow:

1. Background thread monitors expiring access
2. Execute `share-record -a revoke -e user@company.com <record_uid>`
3. Notify user of access expiration

## Configuration Methods

### Interactive Setup:
```bash
My Vault> service-create
# ... follow prompts including Slack Integration (y/n)
```

### Streamlined Setup:
```bash
My Vault> service-create -p 8080 -sbt xoxb-your-token -sss your-secret -sac C1234567890 -c 'get,share-record'
```

### CLI Parameters:
- `-sbt, --slack_bot_token`: Slack bot token for integration
- `-sss, --slack_signing_secret`: Slack signing secret for verification
- `-sac, --slack_approval_channel`: Slack channel ID for approval requests
- `-ser, --slack_eligible_requestors`: Comma-separated list of eligible requestor emails
- `-sap, --slack_approvers`: Comma-separated list of approver emails
- `-sra, --slack_required_approvals`: Number of required approvals (default: 1)

## Files Created/Modified

### ✅ New Files Created:

- `keepercommander/service/api/slack.py` - Slack webhook endpoints
- `keepercommander/service/slack/__init__.py` - Module initialization
- `keepercommander/service/slack/slack_client.py` - Slack API wrapper
- `keepercommander/service/slack/approval_manager.py` - Request tracking & workflow
- `keepercommander/service/slack/message_builder.py` - Slack message formatting
- `keepercommander/service/slack/config.py` - Configuration management
- `keepercommander/service/slack/scheduled_tasks.py` - Background expiration tasks

### ✅ Modified Files:

- `keepercommander/service/api/routes.py` - Register Slack blueprint
- `keepercommander/service/app.py` - Initialize Slack services on startup
- `keepercommander/service/config/service_config.py` - Add Slack config defaults
- `keepercommander/service/config/models.py` - Add Slack config fields
- `keepercommander/service/commands/create_service.py` - Add Slack CLI parameters
- `keepercommander/service/commands/service_config_handlers.py` - Add Slack configuration logic
- `keepercommander/service/README.md` - Add Slack integration documentation

## ✅ Implementation Status: COMPLETE

All todos have been implemented and the Slack integration is fully functional and embedded in Commander Service Mode.

## Key Technical Decisions

- **In-memory storage**: Simple dict-based tracking (sufficient for single-instance deployments)
- **Existing command integration**: Leverage `share-record` command through `CommandExecutor`
- **Background thread**: Single daemon thread for scheduled access cleanup
- **Error handling**: Graceful degradation if Slack is unavailable
- **Security**: Verify Slack signatures, validate record access permissions
- **Configuration**: Integrated with existing service-create command for unified setup
