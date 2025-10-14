from setuptools import setup

try:
    from keepercommander.qrc import ext_modules
except ImportError:
    ext_modules = []

if __name__ == '__main__':
    setup(ext_modules=ext_modules)