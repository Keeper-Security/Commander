# How to improve hacking codes
1. Logging: Add code location(filename and line number) message : basicConfig(format=%(filename)s(%(lineno)d)[%(message)s]
2. Disable rescue from any exceptions: Show exception trace for faster debugging.