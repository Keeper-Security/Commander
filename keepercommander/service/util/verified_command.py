class Verifycommand:
    @staticmethod
    def is_append_command(command):
        """
        Returns True if the command is 'append-notes' and '--notes' is NOT present.
        """
        if len(command) < 1:
            return False
        if command[0] == "append-notes" and not any("--notes" in arg for arg in command):
            return True
        return False