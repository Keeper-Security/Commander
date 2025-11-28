import ctypes
import os
import shutil
import sys
import subprocess

is_windows = sys.platform.startswith('win')
is_macos = sys.platform.startswith('darwin')
is_linux = sys.platform.startswith('linux')

if is_windows:
    # Constants
    LOGON_WITH_PROFILE = 0x00000001
    CREATE_UNICODE_ENVIRONMENT = 0x00000400

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("lpReserved", ctypes.c_wchar_p),
            ("lpDesktop", ctypes.c_wchar_p),
            ("lpTitle", ctypes.c_wchar_p),
            ("dwX", ctypes.c_ulong),
            ("dwY", ctypes.c_ulong),
            ("dwXSize", ctypes.c_ulong),
            ("dwYSize", ctypes.c_ulong),
            ("dwXCountChars", ctypes.c_ulong),
            ("dwYCountChars", ctypes.c_ulong),
            ("dwFillAttribute", ctypes.c_ulong),
            ("dwFlags", ctypes.c_ulong),
            ("wShowWindow", ctypes.c_ushort),
            ("cbReserved2", ctypes.c_ushort),
            ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", ctypes.c_void_p),
            ("hStdOutput", ctypes.c_void_p),
            ("hStdError", ctypes.c_void_p),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", ctypes.c_void_p),
            ("hThread", ctypes.c_void_p),
            ("dwProcessId", ctypes.c_ulong),
            ("dwThreadId", ctypes.c_ulong),
        ]

    # Load function
    CreateProcessWithLogonW = ctypes.windll.advapi32.CreateProcessWithLogonW
    CreateProcessWithLogonW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
        ctypes.c_ulong, ctypes.c_wchar_p, ctypes.c_wchar_p,
        ctypes.c_ulong, ctypes.c_void_p, ctypes.c_wchar_p,
        ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESS_INFORMATION)
    ]
    CreateProcessWithLogonW.restype = ctypes.c_bool

    FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
    FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
    FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

    # Get the error message
    flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS

    def get_error_message(error_code):    # type: (int) -> str
        message_buffer = ctypes.create_unicode_buffer(0)
        length = ctypes.windll.kernel32.FormatMessageW(
            flags,
            None,  # Message source
            error_code,  # Message identifier
            0,  # Language ID
            ctypes.byref(message_buffer),  # Buffer
            0,  # Size
            None  # Arguments
        )
        if length:
            return message_buffer.value.strip()
        return 'Unknown'


def run_as(username, password, application):    # type: (str, str, str) -> None
    if is_windows:
        if '@' in username:
            domain = ''
        else:
            domain, sep, username = username.rpartition('\\')
            if not domain:
                domain = '.'

        application_path = shutil.which(application)
        if not application_path:
            raise Exception(f'Application "{application}" not found. Please use full application path')

        si = STARTUPINFO()
        si.cb = ctypes.sizeof(STARTUPINFO)
        pi = PROCESS_INFORMATION()

        # Launch process
        success = CreateProcessWithLogonW(
            username,
            domain,
            password,
            LOGON_WITH_PROFILE,
            None,
            f'"{application_path}"',
            CREATE_UNICODE_ENVIRONMENT,
            None,
            None,
            ctypes.byref(si),
            ctypes.byref(pi)
        )

        if not success:
            error_code = ctypes.GetLastError()
            raise OSError(f'Failed to launch "{application}" as {username}. Windows Error: {error_code}')
    elif is_macos or is_linux:
        # Find the full path to the application
        application_path = shutil.which(application)
        if not application_path:
            raise Exception(f'Application "{application}" not found. Please use full application path')

        # Check if user exists
        try:
            subprocess.run(['id', '-u', username], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            raise OSError(f'User "{username}" does not exist')

        # Use sudo if we're not root, otherwise use su
        if os.geteuid() != 0:
            cmd = ['sudo', '-u', username, application_path]
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.communicate(input=f'{password}\n'.encode())
        else:
            cmd = ['su', '-', username, '-c', application_path]
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.communicate(input=f'{password}\n'.encode())

        if proc.returncode != 0:
            raise OSError(f'Failed to launch "{application}" as {username}. Error code: {proc.returncode}')
    else:
        raise OSError('Unsupported operating system')
