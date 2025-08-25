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

from flask import Blueprint, request, jsonify
from html import escape
import queue
from ..decorators.unified import unified_api_decorator
from ..util.command_util import CommandExecutor
from ..decorators.logging import logger
from ..core.request_queue import queue_manager

def create_legacy_command_blueprint():
    """Create legacy blueprint for direct/synchronous command execution (non-queue mode)."""
    bp = Blueprint("legacy_command_bp", __name__)
    
    @bp.after_request
    def add_deprecation_header(response):
        """Add deprecation header for legacy API."""
        response.headers['X-API-Deprecated'] = 'true'
        return response
    
    @bp.route("/executecommand", methods=["POST"])
    @unified_api_decorator()
    def execute_command_direct(**kwargs):
        """Execute command directly and return result immediately (legacy behavior)."""
        try:
            logger.warning("DEPRECATED: /api/v1/ usage - migrate to /api/v2/")
            
            request_command = request.json.get("command")
            if not request_command:
                return jsonify({"success": False, "error": "Error: No command provided"}), 400

            command = escape(request_command)
            response, status_code = CommandExecutor.execute(command)
            return response if isinstance(response, bytes) else jsonify(response), status_code

        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return jsonify({"success": False, "error": f"{str(e)}"}), 500

    return bp

def create_command_blueprint():
    """Create Blue Print for Keeper Commander Service."""
    bp = Blueprint("command_bp", __name__)
    
    @bp.route("/executecommand-async", methods=["POST"])
    @unified_api_decorator()
    def execute_command(**kwargs):
        """Submit a command for execution and return request ID immediately."""
        try:
            request_command = request.json.get("command")
            if not request_command:
                return jsonify({"success": False, "error": "Error: No command provided"}), 400
                
            command = escape(request_command)
            
            # Submit to queue and return request ID immediately
            try:
                request_id = queue_manager.submit_request(command)
                return jsonify({
                    "success": True,
                    "request_id": request_id,
                    "status": "queued",
                    "message": "Request queued successfully. Use /api/v2/status/<request_id> to check progress, /api/v2/result/<request_id> to get results, or /api/v2/queue/status for queue info."
                }), 202  # 202 Accepted
            except queue.Full:
                return jsonify({
                    "success": False, 
                    "error": "Error: Request queue is full. Please try again later."
                }), 503  # 503 Service Unavailable
                
        except Exception as e:
            logger.error(f"Error submitting request: {e}")
            return jsonify({"success": False, "error": f"{str(e)}"}), 500

    @bp.route("/status/<request_id>", methods=["GET"])
    @unified_api_decorator()
    def get_request_status(request_id, **kwargs):
        """Get the status of a specific request."""
        try:
            status_info = queue_manager.get_request_status(request_id)
            if status_info is None:
                return jsonify({
                    "success": False,
                    "error": "Error: Request not found"
                }), 404
                
            return jsonify({
                "success": True,
                "request_id": request_id,
                **status_info
            }), 200
            
        except Exception as e:
            logger.error(f"Error getting request status: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @bp.route("/result/<request_id>", methods=["GET"])
    @unified_api_decorator()
    def get_request_result(request_id, **kwargs):
        """Get the result of a completed request."""
        try:
            result_data = queue_manager.get_request_result(request_id)
            if result_data is None:
                # Check if request exists but isn't completed
                status_info = queue_manager.get_request_status(request_id)
                if status_info is None:
                    return jsonify({
                        "success": False,
                        "error": "Error: Request not found"
                    }), 404
                else:
                    return jsonify({
                        "success": False,
                        "error": "Error: Request not completed yet",
                        "status": status_info["status"]
                    }), 202  # 202 Accepted (still processing)
            
            result, status_code = result_data
            return result if isinstance(result, bytes) else jsonify(result), status_code
            
        except Exception as e:
            logger.error(f"Error getting request result: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @bp.route("/queue/status", methods=["GET"])
    @unified_api_decorator()
    def get_queue_status(**kwargs):
        """Get overall queue status information."""
        try:
            queue_status = queue_manager.get_queue_status()
            return jsonify({
                "success": True,
                **queue_status
            }), 200
            
        except Exception as e:
            logger.error(f"Error getting queue status: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    return bp