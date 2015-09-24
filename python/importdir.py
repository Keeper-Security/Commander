import os
import re
import sys

def do(path, env):
    __do(path, env)

__module_file_regexp = "(.+)\.py(c?)$"

def __get_module_names_in_dir(path):
    result = set()

    for entry in os.listdir(path):
        if os.path.isfile(os.path.join(path, entry)):
            regexp_result = re.search(__module_file_regexp, entry)
            if regexp_result:
                result.add(regexp_result.groups()[0])

    return result

def __do(path, env):
    sys.path.append(path)
    for module_name in sorted(__get_module_names_in_dir(path)):
        env[module_name] = __import__(module_name)
