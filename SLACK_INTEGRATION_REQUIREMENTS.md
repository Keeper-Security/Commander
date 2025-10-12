# Slack Commander Integration - Requirements

## Project Goal

Create a Slack App integrated into Commander Service Mode that enables approval-based temporary access to Keeper records through Slack.

## Core Requirements

### 1. Access Request Flow

**User Action:**
- A user can request access to a Keeper Record UID inside Slack
- Request format: `@keeper-bot request access <record_uid> for <duration>`
- Default duration: 30 minutes
- Supported durations: minutes (m), hours (h), days (d)

**Approval Channel:**
- A designated Slack channel containing approvers receives the request
- Request displays:
  - Requester's email
  - Record UID
  - Requested duration
  - Interactive approve/deny buttons

### 2. Approval Process

**Approval Requirements:**
- Configurable number of approvals required (default: 1 approval)
- Any single denial immediately cancels the request
- Approvers interact via Slack buttons (no CLI required)
- Self-approval is not permitted

**Authorization Lists (Optional):**
- **Eligible Requestors**: List of email addresses who can request access
  - If empty/not configured: All users can request
- **Approvers**: List of email addresses who can approve requests
  - If empty/not configured: Any member of the approval channel can approve

### 3. Access Granting

**On Approval:**
- Commander shares the record with the requester in **view-only mode**
- Share duration matches the requested time
- User receives a private Slack message with:
  - Approval confirmation
  - Link to the Keeper web vault with the specific record
  - Duration of access

**On Denial:**
- User receives a private Slack message with denial notification
- No access is granted

### 4. Access Expiration

**Automatic Revocation:**
- After the specified duration (e.g., 30 minutes), the record is automatically unshared
- User receives a notification that their access has expired
- Background process handles cleanup without manual intervention

## Configuration Requirements

### Setup Method

- Configuration managed through Commander's `service-create` command
- Settings stored in Commander service configuration file
- No separate environment files needed

### Required Settings

1. **Slack Bot Token** (xoxb-...)
2. **Slack Signing Secret** (for request verification)
3. **Slack Approval Channel ID** (C...)

### Optional Settings

1. **Eligible Requestor Emails** (comma-separated)
   - Default: Empty (all users can request)
2. **Approver Emails** (comma-separated)
   - Default: Empty (any channel member can approve)
3. **Required Number of Approvals**
   - Default: 1

## Technical Requirements

### Integration Points

- Embedded directly into Commander Service Mode (no separate service)
- Uses existing Commander `share-record` command for access control
- Integrates with Commander service configuration system

### Deployment Assumptions

- Commander Service Mode is already deployed and accessible
- Service is exposed via ngrok, cloudflare tunnel, or self-hosted with public URL
- Slack app has necessary OAuth scopes and webhook URLs configured

### Security

- Slack request signature verification
- Validation that requested records exist and are accessible
- Audit logging of all requests and approvals
- No storage of sensitive record data in Slack

## User Experience Requirements

### For Requestors

- Simple mention-based command syntax
- Clear confirmation when request is submitted
- Private notification of approval/denial
- Direct link to access approved record
- Notification when access expires

### For Approvers

- Clear request details displayed
- One-click approve/deny buttons
- Real-time updates as approvals accumulate
- No CLI or technical knowledge required

### Help System

- Built-in help command: `@keeper-bot help`
- Shows usage examples and syntax

## Out of Scope

- Multi-approval workflows with different approval tiers
- Permanent access grants (all access is temporary)
- Record modification through Slack
- Bulk record access requests
- Custom approval routing logic
