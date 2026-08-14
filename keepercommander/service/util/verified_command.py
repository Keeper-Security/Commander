class Verifycommand:
    # pam tunnel aliases: start=s, list=l, stop=x, edit=e, diagnose=d
    # (see PAMTunnelCommand.register_command in tunnel_and_connections.py)
    _PAM_TUNNEL_ALIASES = {
        's': 'start',
        'l': 'list',
        'x': 'stop',
        'e': 'edit',
        'd': 'diagnose',
    }
    _PAM_TUNNEL_ALLOWED = frozenset({'edit'})
    # Aliases from record.py — CommandExecutor checks tokens before cli expands them.
    _RECORD_EDIT_COMMANDS = frozenset({'record-add', 'ra', 'record-update', 'ru'})

    @staticmethod
    def validate_service_mode_restrictions(command_tokens):
        """Run Service Mode bans on executor tokens (shlex); error string or None."""
        if not command_tokens:
            return None

        for validator in (
            Verifycommand.validate_service_mode_pam_tunnel_command,
            Verifycommand.validate_service_mode_download_attachment_command,
            Verifycommand.validate_service_mode_upload_attachment_command,
            Verifycommand.validate_service_mode_record_file_attachment_command,
        ):
            error = validator(command_tokens)
            if error:
                return error
        return None

    @staticmethod
    def validate_service_mode_pam_tunnel_command(command_tokens):
        """Allow only pam tunnel edit in Service Mode; error string or None."""
        if not command_tokens or len(command_tokens) < 2:
            return None

        tokens_l = [t.lower() for t in command_tokens]
        if tokens_l[0] != 'pam' or tokens_l[1] not in ('tunnel', 't'):
            return None

        # Default verb matches PAMTunnelCommand.default_verb ('list')
        verb = tokens_l[2] if len(tokens_l) >= 3 else 'list'
        verb = Verifycommand._PAM_TUNNEL_ALIASES.get(verb, verb)
        if verb in Verifycommand._PAM_TUNNEL_ALLOWED:
            return None
        return (
            'pam tunnel commands other than edit are not available in Service Mode'
        )

    @staticmethod
    def validate_service_mode_download_attachment_command(command_tokens):
        """Block download-attachment in Service Mode; error string or None."""
        if not command_tokens:
            return None
        if command_tokens[0].lower() not in ('download-attachment', 'da'):
            return None
        return (
            'Downloading attachments to the local filesystem is not permitted '
            'through Service Mode'
        )

    @staticmethod
    def validate_service_mode_upload_attachment_command(command_tokens):
        """Block upload-attachment in Service Mode; error string or None."""
        if not command_tokens:
            return None
        if command_tokens[0].lower() not in ('upload-attachment', 'ua'):
            return None
        return (
            'Uploading attachments from the local filesystem is not permitted '
            'through Service Mode'
        )

    @staticmethod
    def validate_service_mode_record_file_attachment_command(command_tokens):
        """Block record-add/update (and ra/ru) file fields in Service Mode; error or None."""
        if not command_tokens:
            return None
        # Tokens are checked before cli alias expansion, so list ra/ru explicitly.
        if command_tokens[0].lower() not in Verifycommand._RECORD_EDIT_COMMANDS:
            return None
        if not any(Verifycommand._is_record_file_attachment_arg(tok) for tok in command_tokens):
            return None
        return (
            'File attachments by local path are not permitted through Service Mode'
        )

    @staticmethod
    def _is_record_file_attachment_arg(token):
        """True when parse_field would treat this token as a file attachment field."""
        if not token or '=' not in token:
            return False
        # Mirror RecordEditMixin.parse_field field-name normalization.
        name = token.split('=', 1)[0].lower()
        if name.startswith('f.') or name.startswith('c.'):
            name = name[2:]
        return name.split('.', 1)[0] == 'file'

    @staticmethod
    def validate_append_command(command):
        """
        Validates 'append-notes' command and returns error message if invalid.
        Returns None if valid, error message string if invalid.
        """
        if not command or command[0] != "append-notes":
            return None
        
        has_notes = False
        for arg in command[1:]:
            if arg.startswith("--notes="):
                # Check if --notes= has a value after the equals sign
                notes_value = arg[8:]  # Everything after "--notes="
                has_notes = bool(notes_value.strip())
                break
            elif arg == "--notes":
                # Check for a value after --notes flag
                arg_index = command.index(arg)
                if arg_index + 1 < len(command) and not command[arg_index + 1].startswith("-"):
                    notes_value = command[arg_index + 1]
                    has_notes = bool(notes_value.strip())
                break
        
        if not has_notes:
            return "Missing required parameter: --notes with non-empty value"
        return None
    
    @staticmethod
    def validate_mkdir_command(command):
        """
        Validates 'mkdir' command and returns error message if invalid.
        Returns None if valid, error message string if invalid.
        """
        if not command or command[0] != "mkdir":
            return None
        
        has_sf_or_uf = False
        has_name = False
        
        for arg in command[1:]:
            # Check for shared folder or user folder flags
            if arg in ["-sf", "--shared-folder", "-uf", "--user-folder"]:
                has_sf_or_uf = True
            # Check for folder name (non-flag argument)
            elif not arg.startswith("-"):
                has_name = True
        
        missing_params = []
        if not has_sf_or_uf:
            missing_params.append("folder type flag (-sf/--shared-folder for shared folder or -uf/--user-folder for user folder)")
        if not has_name:
            missing_params.append("folder name")
        
        if missing_params:
            return f"Missing required parameters: {' and '.join(missing_params)}"
        return None

    @staticmethod
    def validate_transform_folder_command(command):
        """
        Validates 'transform-folder' command and returns error message if invalid.
        Returns None if valid, error message string if invalid.
        """
        if not command or command[0] != "transform-folder":
            return None
        
        has_force_flag = False
        has_folder_uid = False
        
        for arg in command[1:]:
            # Check for -f or --force flag
            if arg in ["-f", "--force"]:
                has_force_flag = True
            # Check for folder UID (non-flag argument)
            elif not arg.startswith("-"):
                has_folder_uid = True
        
        missing_params = []
        if not has_force_flag:
            missing_params.append("-f/--force flag to bypass interactive confirmation")
        if not has_folder_uid:
            missing_params.append("folder UID or path")
        
        if missing_params:
            return f"Missing required parameters: {' and '.join(missing_params)}"
        return None

    @staticmethod
    def _enterprise_user_add_roles(command):
        """Collect --add-role values from an enterprise-user command token list."""
        roles = []
        i = 1
        while i < len(command):
            arg = command[i]
            if arg == '--add-role' and i + 1 < len(command) and not command[i + 1].startswith('-'):
                roles.append(command[i + 1])
                i += 2
                continue
            if arg.startswith('--add-role='):
                roles.append(arg.split('=', 1)[1])
            i += 1
        return roles

    @staticmethod
    def _is_managed_admin_role(params, role_name):
        """True when the role has administrative (managed node) permissions."""
        if not params or not getattr(params, 'enterprise', None):
            return False
        role_id = None
        for role in params.enterprise.get('roles') or []:
            display = ((role.get('data') or {}).get('displayname') or '').strip()
            if str(role.get('role_id')) == str(role_name) or display.lower() == str(role_name).lower():
                role_id = role.get('role_id')
                break
        if role_id is None:
            return False
        return any(
            mn.get('role_id') == role_id
            for mn in (params.enterprise.get('managed_nodes') or [])
        )

    @classmethod
    def validate_enterprise_user_add_role_force(cls, command, params=None):
        """
        Admin roles prompt for confirmation on --add-role. Service Mode cannot
        answer that prompt, so require -f/--force (same pattern as transform-folder).
        Skips invite/--add flows (roles are deferred, not applied interactively).
        """
        if not command or command[0] not in ('enterprise-user', 'eu'):
            return None

        # Invite queues roles for later; no interactive admin-role prompt here.
        if any(a in ('--invite', '--add') for a in command[1:]):
            return None

        roles = cls._enterprise_user_add_roles(command)
        if not roles:
            return None

        has_force = any(a in ('-f', '--force') for a in command[1:])
        if has_force:
            return None

        if params is not None:
            try:
                from ... import api
                if not getattr(params, 'enterprise', None):
                    api.query_enterprise(params)
            except Exception:
                pass
            if not any(cls._is_managed_admin_role(params, role) for role in roles):
                return None

        return (
            'Missing required parameters: -f/--force flag to bypass '
            'interactive confirmation'
        )
