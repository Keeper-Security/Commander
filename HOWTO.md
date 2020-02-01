# How to improve hacking codes
1. Logging: Add code location(module name and function name) in message : basicConfig(format=
__logging_format__ = "%(levelname)s: %(message)s in %(module)s.%(funcName)s at %(asctime)s"
2. Disable rescue from any exceptions: Show exception trace for faster debugging.