import contextlib
import io
import os


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

    # Legacy Commands category — plugin-based rotation/connection commands have no safe Service Mode form
    # and are blocked unconditionally, regardless of what an API key's command_list allows.
    _LEGACY_COMMANDS = frozenset({
        'rotate', 'r',
        'connect', 'ssh', 'ssh-agent', 'rdp', 'rsync',
        'set', 'echo',
        'mysql', 'postgresql', 'pg',
    })
    _LEGACY_COMMAND_MSG = (
        'Legacy commands are not permitted through Service Mode'
    )

    # GroupCommand.execute_args (commands/base.py) strips a leading '-- ' at each
    # nested group boundary, desyncing position-based checks below (e.g. pam tunnel).
    _DOUBLE_DASH_MSG = (
        "The '--' argument separator is not permitted through Service Mode"
    )

    # WARNING: everything below is a DENYLIST. Any command/flag that reads or
    # writes a host file and is NOT enumerated here is allowed by default.
    # Adding a new command with local file I/O? Add it here, or it silently
    # bypasses Service Mode's "no host filesystem access" boundary.
    #
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
    # import --format values that name an account/API/URL source, not a local
    # file (importer/commands.py choices). Any format NOT in this set is treated as file-based by default.
    _IMPORT_FORMATS_WITHOUT_FILE = frozenset({
        'lastpass', 'manageengine', 'thycotic', 'cyberark', 'cyberark_portal',
    })
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
    def validate_service_mode_restrictions(command_tokens, request_temp_dir=None):
        """Run Service Mode bans on executor tokens (shlex); error string or None."""
        if not command_tokens:
            return None

        for validator in (
            Verifycommand.validate_service_mode_double_dash,
            Verifycommand.validate_service_mode_legacy_command,
            Verifycommand.validate_service_mode_pam_tunnel_command,
            Verifycommand.validate_service_mode_download_attachment_command,
            Verifycommand.validate_service_mode_upload_attachment_command,
            Verifycommand.validate_service_mode_record_file_attachment_command,
            Verifycommand.validate_service_mode_host_filesystem_command,
            Verifycommand.validate_service_mode_host_path_args,
            Verifycommand.validate_service_mode_file_input_command,
        ):
            error = validator(command_tokens, request_temp_dir)
            if error:
                return error
        return None

    @staticmethod
    def validate_service_mode_double_dash(command_tokens, request_temp_dir=None):
        """Block bare '--' anywhere in Service Mode input; error or None."""
        if '--' in command_tokens:
            return Verifycommand._DOUBLE_DASH_MSG
        return None

    @staticmethod
    def validate_service_mode_legacy_command(command_tokens, request_temp_dir=None):
        """Block legacy commands in Service Mode; error or None."""
        if not command_tokens:
            return None
        if command_tokens[0].lower() not in Verifycommand._LEGACY_COMMANDS:
            return None
        return Verifycommand._LEGACY_COMMAND_MSG

    @staticmethod
    def validate_service_mode_pam_tunnel_command(command_tokens, request_temp_dir=None):
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
    def validate_service_mode_download_attachment_command(command_tokens, request_temp_dir=None):
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
    def validate_service_mode_upload_attachment_command(command_tokens, request_temp_dir=None):
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
    def validate_service_mode_record_file_attachment_command(command_tokens, request_temp_dir=None):
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
    def validate_service_mode_host_filesystem_command(command_tokens, request_temp_dir=None):
        """Block commands that always touch the host filesystem; error or None."""
        if not command_tokens:
            return None
        if command_tokens[0].lower() not in Verifycommand._HOST_FS_COMMANDS:
            return None
        return Verifycommand._HOST_FS_MSG

    @staticmethod
    def validate_service_mode_host_path_args(command_tokens, request_temp_dir=None):
        """Block host-path flags (--output, --filename, …); error or None."""
        if not command_tokens:
            return None

        tokens = command_tokens
        cmd0 = tokens[0].lower()

        # PDF always requires an on-disk output file. Routed through
        # _option_values so abbreviations (--form, --fmt=pdf, …) are caught too.
        for value in Verifycommand._option_values(tokens, '--format'):
            if value.lower() == 'pdf':
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
            if not Verifycommand._is_service_temp_path(value, request_temp_dir):
                return Verifycommand._HOST_FS_MSG

        # pam project import/extend use -f as --filename (not --force).
        if Verifycommand._is_pam_project_filename_cmd(tokens):
            for value in Verifycommand._option_values(tokens, '-f'):
                if not Verifycommand._is_service_temp_path(value, request_temp_dir):
                    return Verifycommand._HOST_FS_MSG

        for value in Verifycommand._option_values(tokens, '--file'):
            if Verifycommand._looks_like_local_path(value):
                if not Verifycommand._is_service_temp_path(value, request_temp_dir):
                    return Verifycommand._HOST_FS_MSG

        for value in Verifycommand._option_values(tokens, '--output'):
            if value.lower() not in Verifycommand._NON_PATH_OUTPUT_VALUES:
                return Verifycommand._HOST_FS_MSG

        # generate / pam project export use -o as a file path (not mode).
        if cmd0 in Verifycommand._GENERATE_COMMAND_NAMES or Verifycommand._is_pam_project_export(tokens):
            for value in Verifycommand._option_values(tokens, '-o'):
                if value.lower() not in Verifycommand._NON_PATH_OUTPUT_VALUES:
                    return Verifycommand._HOST_FS_MSG

        # transfer-user (tu) @filename mapping files - scoped to that command
        # only, since '@value' is a legitimate argument shape elsewhere.
        if cmd0 in ('transfer-user', 'tu'):
            for tok in tokens[1:]:
                if tok.startswith('@') and Verifycommand._looks_like_local_path(tok[1:]):
                    return Verifycommand._HOST_FS_MSG

        return None

    @staticmethod
    def validate_service_mode_file_input_command(command_tokens, request_temp_dir=None):
        """Allow import/enterprise-push only with FILEDATA temp paths; error or None."""
        if not command_tokens:
            return None
        cmd0 = command_tokens[0].lower()
        if cmd0 not in Verifycommand._FILE_INPUT_COMMANDS:
            return None

        if cmd0 == 'import':
            from ...importer.commands import import_parser
            ns = Verifycommand._safe_parse(import_parser, command_tokens[1:])
            if ns is None:
                # Malformed for the real parser too; it will reject this itself.
                return None
            fmt = (ns.format or '').lower()
            if fmt in Verifycommand._IMPORT_FORMATS_WITHOUT_FILE:
                return None
            if ns.name and not Verifycommand._is_service_temp_path(ns.name, request_temp_dir):
                return Verifycommand._HOST_FS_MSG
            return None

        if cmd0 == 'enterprise-push':
            from ...commands.enterprise_push import enterprise_push_parser
            ns = Verifycommand._safe_parse(enterprise_push_parser, command_tokens[1:])
            if ns is None:
                return None
            if ns.file and not Verifycommand._is_service_temp_path(ns.file, request_temp_dir):
                return Verifycommand._HOST_FS_MSG
            return None

        return None

    @staticmethod
    def _safe_parse(parser, tokens):
        """Resolve tokens via the command's real argparse parser; None if it can't be resolved.

        Used instead of hand-scanning tokens so we get the parser's own
        distinction between a positional value and a flag's value -- the
        raw tokens alone don't tell you that.
        """
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                ns, _ = parser.parse_known_args(tokens)
            return ns
        except SystemExit:
            return None
        except Exception:
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

    # Flags we separately check for. Some are literal prefixes of others
    # (--output/--output-dir, --file/--filename, --file/--file-cache) - a
    # token that's a *complete* match for one of these is a distinct flag in
    # its own right, never an abbreviation attempt at a different one.
    _KNOWN_DANGEROUS_FLAGS = frozenset({
        '--output', '--filename', '--file', '--format',
        '--out-dir', '--output-dir', '--from-file', '--file-cache',
        '--keepass-key-file', '--config',
    })

    @staticmethod
    def _flag_matches(tok_name, flag):
        """True if tok_name is exactly flag, or an unambiguous long-option
        abbreviation of it (argparse's allow_abbrev default -- almost no
        parser in this codebase opts out of it, so '--out' really does mean
        '--output' to the command that will actually run).

        Short options ('-o', '-f') are never abbreviated by argparse, so
        those only ever match exactly.
        """
        if tok_name == flag:
            return True
        # Reject bare '--' (argparse's "end of options" marker), anything
        # that isn't a '--long' option on both sides, and anything that's
        # already a complete, distinct flag of its own.
        if len(tok_name) <= 2 or not tok_name.startswith('--') or not flag.startswith('--'):
            return False
        if tok_name in Verifycommand._KNOWN_DANGEROUS_FLAGS:
            return False
        return flag.startswith(tok_name)

    @staticmethod
    def _has_option(tokens, flag):
        """True if flag, flag=value, or an abbreviation of flag appears in tokens."""
        flag_l = flag.lower()
        for tok in tokens[1:]:
            name = tok.lower().split('=', 1)[0]
            if Verifycommand._flag_matches(name, flag_l):
                return True
        return False

    @staticmethod
    def _option_values(tokens, flag):
        """Yield values for --flag value / --flag=value (and short -o value),
        matching flag itself or an unambiguous abbreviation of it."""
        flag_l = flag.lower()
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            lower = tok.lower()
            name, sep, _ = lower.partition('=')
            if sep and Verifycommand._flag_matches(name, flag_l):
                yield tok.split('=', 1)[1]
                i += 1
                continue
            if not sep and Verifycommand._flag_matches(name, flag_l):
                # Consume the next token as the value even if it starts with
                # '-' (e.g. a path or FILEDATA placeholder) -- these flags are
                # all required-argument (action='store'), so skipping a
                # dash-leading value here let it slip past every check below.
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
    def _is_service_temp_path(path, request_temp_dir):
        """True when path resolves under *this request's* own temp directory, not just anywhere under the
        shared OS temp root -- other processes/users can also write there.
        """
        if not path or not request_temp_dir:
            return False
        try:
            expanded = os.path.expanduser(path)
            # Resolve the parent, not the nonexistent leaf -- Windows only expands
            # 8.3 short names for path segments that already exist on disk.
            parent = os.path.realpath(os.path.dirname(expanded) or '.')
            resolved = os.path.normcase(os.path.join(parent, os.path.basename(expanded)))
            root = os.path.normcase(os.path.realpath(request_temp_dir))
            return resolved == root or resolved.startswith(root + os.sep)
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
