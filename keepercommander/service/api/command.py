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

from flask import Blueprint, request, jsonify, Response
import queue
from typing import Tuple, Union
from ..decorators.unified import unified_api_decorator
from ..util.command_util import CommandExecutor
from ..decorators.logging import logger
from ..core.request_queue import queue_manager
from ..util.request_validation import RequestValidator

def create_legacy_command_blueprint():
    """Create legacy blueprint for direct/synchronous command execution (non-queue mode)."""
    bp = Blueprint("legacy_command_bp", __name__)
    
    @bp.after_request
    def add_legacy_header(response):
        """Add legacy header for legacy API."""
        response.headers['X-API-Legacy'] = 'true'
        return response
    
    @bp.route("/executecommand", methods=["POST"])
    @unified_api_decorator()
    def execute_command_direct(**kwargs) -> Tuple[Union[Response, bytes], int]:
        """Execute command directly and return result immediately (V1 API behavior)."""
        temp_files = []
        try:
            json_error = RequestValidator.validate_request_json()
            if json_error:
                return json_error
            
            command, validation_error = RequestValidator.validate_and_escape_command(request.json)
            if validation_error:
                return validation_error
            
            # Process file data if present
            processed_command, temp_files = RequestValidator.process_file_data(request.json, command)
                
            response, status_code = CommandExecutor.execute(processed_command)
            
            # If we get a busy response, add v1-specific message
            if (isinstance(response, dict) and 
                "temporarily busy" in str(response.get("error", "")).lower()):
                response["message"] = "Note: api/v1/executecommand only supports a single request at a time."
                status_code = 503
            
            return response if isinstance(response, bytes) else jsonify(response), status_code

        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return jsonify({"status": "error", "error": f"Error: {str(e)}"}), 500
        finally:
            # Clean up temporary files
            RequestValidator.cleanup_temp_files(temp_files)

    return bp

def create_command_blueprint():
    """Create Blue Print for Keeper Commander Service."""
    bp = Blueprint("command_bp", __name__)
    
    @bp.route("/executecommand-async", methods=["POST"])
    @unified_api_decorator()
    def execute_command(**kwargs) -> Tuple[Response, int]:
        """Submit a command for execution and return request ID immediately."""
        temp_files = []
        try:
            json_error = RequestValidator.validate_request_json()
            if json_error:
                return json_error
            
            command, validation_error = RequestValidator.validate_and_escape_command(request.json)
            if validation_error:
                return validation_error
            
            # Process file data if present
            processed_command, temp_files = RequestValidator.process_file_data(request.json, command)
            
            # Submit to queue and return request ID immediately
            try:
                request_id = queue_manager.submit_request(processed_command, temp_files)
                return jsonify({
                    "success": True,
                    "request_id": request_id,
                    "status": "queued",
                    "message": "Request queued successfully. Use /api/v2/status/<request_id> to check progress, /api/v2/result/<request_id> to get results, or /api/v2/queue/status for queue info."
                }), 202  # 202 Accepted
            except queue.Full:
                # Clean up temp files if queue is full
                RequestValidator.cleanup_temp_files(temp_files)
                return jsonify({
                    "status": "error", 
                    "error": "Error: Request queue is full. Please try again later."
                }), 503  # 503 Service Unavailable
                
        except Exception as e:
            logger.error(f"Error submitting request: {e}")
            # Clean up temp files on error
            RequestValidator.cleanup_temp_files(temp_files)
            return jsonify({"status": "error", "error": f"{str(e)}"}), 500

    @bp.route("/status/<request_id>", methods=["GET"])
    @unified_api_decorator()
    def get_request_status(request_id: str, **kwargs) -> Tuple[Response, int]:
        """Get the status of a specific request."""
        try:
            status_info = queue_manager.get_request_status(request_id)
            if status_info is None:
                return jsonify({
                    "status": "error",
                    "error": "Error: Request not found"
                }), 404
                
            return jsonify({
                "success": True,
                "request_id": request_id,
                **status_info
            }), 200
            
        except Exception as e:
            logger.error(f"Error getting request status: {e}")
            return jsonify({"status": "error", "error": str(e)}), 500

    @bp.route("/result/<request_id>", methods=["GET"])
    @unified_api_decorator()
    def get_request_result(request_id: str, **kwargs) -> Tuple[Union[Response, bytes], int]:
        """Get the result of a completed request."""
        try:
            result_data = queue_manager.get_request_result(request_id)
            if result_data is None:
                # Check if request exists but isn't completed
                status_info = queue_manager.get_request_status(request_id)
                if status_info is None:
                    return jsonify({
                        "status": "error",
                        "error": "Error: Request not found"
                    }), 404
                else:
                    return jsonify({
                        "status": "error",
                        "error": "Error: Request not completed yet",
                        "status": status_info["status"]
                    }), 202  # 202 Accepted (still processing)
            
            result, status_code = result_data
            return result if isinstance(result, bytes) else jsonify(result), status_code
            
        except Exception as e:
            logger.error(f"Error getting request result: {e}")
            return jsonify({"status": "error", "error": str(e)}), 500

    @bp.route("/queue/status", methods=["GET"])
    @unified_api_decorator()
    def get_queue_status(**kwargs) -> Tuple[Response, int]:
        """Get overall queue status information."""
        try:
            queue_status = queue_manager.get_queue_status()
            return jsonify({
                "success": True,
                **queue_status
            }), 200
            
        except Exception as e:
            logger.error(f"Error getting queue status: {e}")
            return jsonify({"status": "error", "error": str(e)}), 500

    return bp
