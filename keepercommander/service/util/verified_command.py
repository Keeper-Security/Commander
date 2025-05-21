class Verifycommand:
    @staticmethod
    def is_append_command(command):
        """
        Returns True if the command is 'append-notes' and '--notes' is NOT present.
        """
        if not command or command[0] != "append-notes":
            return False
        for arg in command[1:]:
            if arg.startswith("--notes="):
                return arg == "--notes="
        return True