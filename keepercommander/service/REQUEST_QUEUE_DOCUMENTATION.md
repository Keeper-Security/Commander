# Service Mode Request Queue System

## Overview

The Service Mode Request Queue System provides sequential request processing with unique request tracking, ensuring no requests are dropped and maintaining data integrity through single-threaded execution.

## Features

### Core Functionality
- **Request Queuing**: All incoming requests are queued instead of being processed immediately
- **Sequential Processing**: Requests are processed one at a time in FIFO order
- **Unique Request IDs**: Each request receives a UUID for tracking
- **Status Tracking**: Full lifecycle tracking from queued to completed
- **Result Retrieval**: Asynchronous result retrieval using request IDs
- **Automatic Cleanup**: Expired and old requests are automatically cleaned up

### Benefits
- **No Dropped Requests**: All requests are queued and processed
- **Predictable Behavior**: Single-threaded execution maintains data integrity
- **Full Transparency**: Complete visibility into queue status and request progress
- **Scalability**: Can handle burst traffic without losing requests

## API Endpoints

### Submit Request
```bash
POST /api/v1/executecommand
```

**Request Body:**
```json
{
    "command": "tree"
}
```

**Response (202 Accepted):**
```json
{
    "success": true,
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "queued",
    "message": "Request queued successfully. Use /status/<request_id> to check progress."
}
```

### Check Request Status
```bash
GET /api/v1/status/<request_id>
```

**Response:**
```json
{
    "success": true,
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "command": "tree",
    "status": "completed",
    "created_at": "2024-01-15T10:30:00.000000",
    "started_at": "2024-01-15T10:30:01.000000",
    "completed_at": "2024-01-15T10:30:03.000000"
}
```

### Get Request Result
```bash
GET /api/v1/result/<request_id>
```

**Response (for completed request):**
```json
{
    "result": "...",
    "status": "success"
}
```

**Response (for pending request - 202 Accepted):**
```json
{
    "success": false,
    "error": "Request not completed yet",
    "status": "processing"
}
```

### Get Queue Status
```bash
GET /api/v1/queue/status
```

**Response:**
```json
{
    "success": true,
    "queue_size": 3,
    "active_requests": 5,
    "completed_requests": 12,
    "currently_processing": "550e8400-e29b-41d4-a716-446655440000",
    "worker_running": true
}
```

## Request States

| State | Description |
|-------|-------------|
| `queued` | Request accepted and waiting in queue |
| `processing` | Currently being executed |
| `completed` | Successfully completed |
| `failed` | Execution failed |
| `expired` | Request timed out before processing |

## Configuration Options

The queue system can be configured through the service configuration:

```yaml
# Queue system settings
queue_max_size: 100          # Maximum number of queued requests
request_timeout: 300         # Request timeout in seconds (5 minutes)
result_retention: 3600       # How long to keep results in seconds (1 hour)
```

### Configuration Parameters

- **`queue_max_size`** (default: 100): Maximum number of requests that can be queued simultaneously
- **`request_timeout`** (default: 300): Time in seconds after which queued requests expire
- **`result_retention`** (default: 3600): Time in seconds to retain completed request results

## Usage Examples

### Submit and Poll Pattern
```bash
# Submit request
RESPONSE=$(curl -s -X POST \
  'http://localhost:8080/api/v1/executecommand' \
  --header 'Content-Type: application/json' \
  --header 'api-key: your-api-key' \
  --data '{"command": "tree"}')

REQUEST_ID=$(echo $RESPONSE | jq -r '.request_id')

# Poll for completion
while true; do
  STATUS=$(curl -s \
    "http://localhost:8080/api/v1/status/$REQUEST_ID" \
    --header 'api-key: your-api-key' | jq -r '.status')
  
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    break
  fi
  
  sleep 1
done

# Get result
curl "http://localhost:8080/api/v1/result/$REQUEST_ID" \
  --header 'api-key: your-api-key'
```

### Batch Processing
```bash
# Submit multiple requests
for cmd in "tree" "ls" "search password"; do
  curl -X POST \
    'http://localhost:8080/api/v1/executecommand' \
    --header 'Content-Type: application/json' \
    --header 'api-key: your-api-key' \
    --data "{\"command\": \"$cmd\"}"
done

# Check queue status
curl 'http://localhost:8080/api/v1/queue/status' \
  --header 'api-key: your-api-key'
```

## Error Handling

### Queue Full (503 Service Unavailable)
```json
{
    "success": false,
    "error": "Request queue is full. Please try again later."
}
```

### Request Not Found (404 Not Found)
```json
{
    "success": false,
    "error": "Request not found"
}
```

### Request Failed (500 Internal Server Error)
```json
{
    "error": "Command execution failed: <error message>"
}
```

## Implementation Details

### Thread Safety
- Uses Python's `queue.Queue` for thread-safe request queuing
- Single worker thread processes requests sequentially
- Thread-safe dictionaries for request storage

### Memory Management
- Automatic cleanup of expired requests
- Configurable result retention period
- Bounded queue size prevents memory exhaustion

### Error Recovery
- Failed requests are marked as failed but not retried automatically
- Queue worker continues processing after individual request failures
- Service restart preserves queue state through configuration

## Migration from Synchronous Processing

The queue system is backward compatible:

1. **Existing clients** will receive a 202 status with request ID instead of immediate results
2. **Client updates needed**: Implement polling mechanism to check status and retrieve results
3. **Gradual migration**: Clients can be updated incrementally

### Migration Example

**Before (synchronous):**
```bash
curl -X POST 'http://localhost:8080/api/v1/executecommand' \
  --data '{"command": "tree"}' | jq '.result'
```

**After (asynchronous):**
```bash
# Step 1: Submit request
REQUEST_ID=$(curl -X POST 'http://localhost:8080/api/v1/executecommand' \
  --data '{"command": "tree"}' | jq -r '.request_id')

# Step 2: Wait and get result
sleep 2
curl "http://localhost:8080/api/v1/result/$REQUEST_ID" | jq '.result'
```

## Troubleshooting

### Queue Not Processing Requests
- Check service logs for worker thread errors
- Verify queue worker is running: `GET /api/v1/queue/status`
- Restart service if worker thread has stopped

### High Memory Usage
- Check `completed_requests` count in queue status
- Reduce `result_retention` configuration value
- Increase cleanup frequency by reducing retention time

### Requests Timing Out
- Increase `request_timeout` configuration value
- Check if commands are taking longer than expected
- Monitor queue size to identify bottlenecks

## Performance Considerations

- **Queue Size**: Larger queues use more memory but handle bursts better
- **Retention Period**: Longer retention uses more memory but provides better user experience
- **Timeout Values**: Shorter timeouts free resources faster but may interrupt long-running commands

## Security

The queue system maintains all existing security features:
- API key authentication required for all endpoints
- Rate limiting applies to request submission
- IP-based access controls enforced
- Audit logging for all queue operations