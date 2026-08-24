import os
import tempfile


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

    # Commands that always read/write host files (no safe Service Mode form).
    _HOST_FS_COMMANDS = frozenset({
        'run-batch', 'run',
        'export',
        'download-membership',
        'download-record-types',
        'apply-membership',
        'load-record-types',
    })
    # Positional file input; FILEDATA is rewritten to a temp path before execute.
    _FILE_INPUT_COMMANDS = frozenset({'import', 'enterprise-push'})
    # generate's registered alias (commands/utils.py: aliases['gen'] = 'generate').
    _GENERATE_COMMAND_NAMES = frozenset({'generate', 'gen'})
    # pam's 'project' subcommand alias (discoveryrotation.py: register_command('project', ..., 'p')).
    _PAM_PROJECT_ALIASES = {'p': 'project'}
    # pam project's own subcommand aliases (pam_import/commands.py: register_command(...)).
    _PAM_PROJECT_SUBCOMMAND_ALIASES = {'x': 'export', 'i': 'import', 'e': 'extend'}
    # --output values that select a mode/format, not a host path.
    _NON_PATH_OUTPUT_VALUES = frozenset({
        'clipboard', 'stdout', 'stdouthidden', 'variable',
        'token', 'base64', 'json', 'k8s', 'text',
    })
    # Extensions that indicate a local data file (avoid treating emails as paths).
    _LOCAL_FILE_EXTENSIONS = frozenset({
        '.json', '.csv', '.txt', '.yaml', '.yml', '.xml', '.kdbx', '.zip',
        '.pdf', '.ndjson', '.1pif', '.xlsx', '.xls', '.kdb', '.gpg',
    })
    _HOST_FS_MSG = (
        'Local filesystem access is not permitted through Service Mode'
    )

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
            Verifycommand.validate_service_mode_host_filesystem_command,
            Verifycommand.validate_service_mode_host_path_args,
            Verifycommand.validate_service_mode_file_input_command,
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
    def validate_service_mode_host_filesystem_command(command_tokens):
        """Block commands that always touch the host filesystem; error or None."""
        if not command_tokens:
            return None
        if command_tokens[0].lower() not in Verifycommand._HOST_FS_COMMANDS:
            return None
        return Verifycommand._HOST_FS_MSG

    @staticmethod
    def validate_service_mode_host_path_args(command_tokens):
        """Block host-path flags (--output, --filename, …); error or None."""
        if not command_tokens:
            return None

        tokens = command_tokens
        cmd0 = tokens[0].lower()

        # PDF always requires an on-disk output file.
        for i, tok in enumerate(tokens[1:], start=1):
            lower = tok.lower()
            if lower == '--format=pdf':
                return Verifycommand._HOST_FS_MSG
            if lower == '--format' and i + 1 < len(tokens):
                if tokens[i + 1].lower() == 'pdf':
                    return Verifycommand._HOST_FS_MSG

        for flag in ('--out-dir', '--output-dir', '--from-file', '--file-cache',
                     '--keepass-key-file', '-v3f'):
            if Verifycommand._has_option(tokens, flag):
                return Verifycommand._HOST_FS_MSG

        # credential-provision --config is a host YAML path; --config-base64 is OK.
        # Do not ban --config globally — PAM uses it for configuration UIDs.
        if cmd0 in ('credential-provision', 'cp') and Verifycommand._has_option(tokens, '--config'):
            return Verifycommand._HOST_FS_MSG

        for value in Verifycommand._option_values(tokens, '--filename'):
            if not Verifycommand._is_service_temp_path(value):
                return Verifycommand._HOST_FS_MSG

        # pam project import/extend/edit use -f as --filename (not --force).
        if Verifycommand._is_pam_project_filename_cmd(tokens):
            for value in Verifycommand._option_values(tokens, '-f'):
                if not Verifycommand._is_service_temp_path(value):
                    return Verifycommand._HOST_FS_MSG

        for value in Verifycommand._option_values(tokens, '--file'):
            if Verifycommand._looks_like_local_path(value):
                if not Verifycommand._is_service_temp_path(value):
                    return Verifycommand._HOST_FS_MSG

        for value in Verifycommand._option_values(tokens, '--output'):
            if value.lower() not in Verifycommand._NON_PATH_OUTPUT_VALUES:
                return Verifycommand._HOST_FS_MSG

        # generate / pam project export use -o as a file path (not mode).
        if cmd0 in Verifycommand._GENERATE_COMMAND_NAMES or Verifycommand._is_pam_project_export(tokens):
            for value in Verifycommand._option_values(tokens, '-o'):
                if value.lower() not in Verifycommand._NON_PATH_OUTPUT_VALUES:
                    return Verifycommand._HOST_FS_MSG

        # transfer-user @filename mapping files
        for tok in tokens[1:]:
            if tok.startswith('@') and Verifycommand._looks_like_local_path(tok[1:]):
                return Verifycommand._HOST_FS_MSG

        return None

    @staticmethod
    def validate_service_mode_file_input_command(command_tokens):
        """Allow import/enterprise-push only with FILEDATA temp paths; error or None."""
        if not command_tokens:
            return None
        if command_tokens[0].lower() not in Verifycommand._FILE_INPUT_COMMANDS:
            return None

        for tok in command_tokens[1:]:
            if tok.startswith('-'):
                continue
            if not Verifycommand._looks_like_local_path(tok):
                continue
            if not Verifycommand._is_service_temp_path(tok):
                return Verifycommand._HOST_FS_MSG
        return None

    @staticmethod
    def _pam_project_verb(command_tokens):
        """Resolve 'pam <project|p> <verb>' (alias-aware) to the verb, or None."""
        if len(command_tokens) < 3:
            return None
        t = [x.lower() for x in command_tokens[:3]]
        if t[0] != 'pam':
            return None
        project = Verifycommand._PAM_PROJECT_ALIASES.get(t[1], t[1])
        if project != 'project':
            return None
        return Verifycommand._PAM_PROJECT_SUBCOMMAND_ALIASES.get(t[2], t[2])

    @staticmethod
    def _is_pam_project_export(command_tokens):
        return Verifycommand._pam_project_verb(command_tokens) == 'export'

    @staticmethod
    def _is_pam_project_filename_cmd(command_tokens):
        return Verifycommand._pam_project_verb(command_tokens) in ('import', 'extend')

    @staticmethod
    def _has_option(tokens, flag):
        """True if flag or flag=value appears in tokens."""
        flag_l = flag.lower()
        prefix = flag_l + '='
        for tok in tokens[1:]:
            lower = tok.lower()
            if lower == flag_l or lower.startswith(prefix):
                return True
        return False

    @staticmethod
    def _option_values(tokens, flag):
        """Yield values for --flag value / --flag=value (and short -o value)."""
        flag_l = flag.lower()
        prefix = flag_l + '='
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            lower = tok.lower()
            if lower.startswith(prefix):
                yield tok.split('=', 1)[1]
                i += 1
                continue
            if lower == flag_l:
                if i + 1 < len(tokens):
                    yield tokens[i + 1]
                    i += 2
                    continue
            i += 1

    @staticmethod
    def _looks_like_local_path(value):
        if not value:
            return False
        if value.startswith(('http://', 'https://')):
            return False
        if value.startswith('~') or '/' in value or '\\' in value:
            return True
        _, ext = os.path.splitext(value)
        return ext.lower() in Verifycommand._LOCAL_FILE_EXTENSIONS

    @staticmethod
    def _is_service_temp_path(path):
        """True when path resolves under the process temp dir (FILEDATA sink)."""
        if not path:
            return False
        try:
            resolved = os.path.realpath(os.path.expanduser(path))
            temp_root = os.path.realpath(tempfile.gettempdir())
            return resolved == temp_root or resolved.startswith(temp_root + os.sep)
        except (OSError, ValueError):
            return False

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
