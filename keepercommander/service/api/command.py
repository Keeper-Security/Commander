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
from ..decorators.unified import unified_api_decorator
from ..util.command_util import CommandExecutor

def create_command_blueprint():
    """Create Blue Print for Keeper Commander Service."""
    bp = Blueprint("command_bp", __name__)
    
    @bp.route("/executecommand", methods=["POST"])
    @unified_api_decorator()
    def execute_command(**kwargs):
        try:
            request_command = request.json.get("command")
            command = escape(request_command)
            response, status_code = CommandExecutor.execute(command)
            return response if isinstance(response, bytes) else jsonify(response), status_code
        except Exception as e:
            return jsonify({"success": False, "error": f"{str(e)}"}), 500

    return bp