from setuptools import Extension
import os

ext_modules = []
qrc_c_source = "keepercommander/qrc/mlkem/fastmathmodule.c"

if os.path.exists(qrc_c_source):
    ext_modules.append(Extension(
        "keepercommander.qrc.mlkem.fastmath",
        sources=[qrc_c_source],
        extra_compile_args=["-std=c99"],
        optional=True
    ))
