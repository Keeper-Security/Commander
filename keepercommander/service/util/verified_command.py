class Verifycommand:
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
                # Check if there's a value after --notes flag
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
    
    # Legacy methods for backward compatibility
    @staticmethod
    def is_append_command(command):
        """Legacy method - returns True if command is invalid."""
        return Verifycommand.validate_append_command(command) is not None
    
    @staticmethod
    def is_mkdir_command(command):
        """Legacy method - returns True if command is invalid."""
        return Verifycommand.validate_mkdir_command(command) is not None
    
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
    
    # Legacy methods for backward compatibility
    @staticmethod
    def is_append_command(command):
        """Legacy method - returns True if command is invalid."""
        return Verifycommand.validate_append_command(command) is not None
    
    @staticmethod
    def is_mkdir_command(command):
        """Legacy method - returns True if command is invalid."""
        return Verifycommand.validate_mkdir_command(command) is not None
    
    @staticmethod
    def is_transform_folder_command(command):
        """Legacy method - returns True if command is invalid."""
        return Verifycommand.validate_transform_folder_command(command) is not None