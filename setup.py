from setuptools import setup

from setuptools.command.install import install as install_command
import os
import subprocess
import shutil
import re


class Wheel(install_command):

    user_options = install_command.user_options + [
        ('whlsrc=', None, "Build a wheel for the python code that is in this directory. Copy into 'libs' directory."),
        ('libdir=', None, "The directory to put the whl files."),
        ('reqfiles=', None, "List of requirement.txt to update."),
    ]

    def initialize_options(self):
        install_command.initialize_options(self)
        self.whlsrc = None
        self.libdir = None
        self.reqfiles = None

    def finalize_options(self):
        install_command.finalize_options(self)

    def run(self):
        global whlsrc
        global libdir
        global reqfiles
        whlsrc = self.whlsrc
        libdir = self.libdir
        reqfiles = self.reqfiles

        if isinstance(reqfiles, list) is False:
            reqfiles = [reqfiles]

        current_dir = os.getcwd()
        try:
            # Get existing fiels in the lib directory.
            os.chdir(self.libdir)
            sp = subprocess.run(["ls"], capture_output=True, text=True)
            existing_whls = []
            for file in sp.stdout.split("\n"):
                if file.endswith("whl") is True:
                    existing_whls.append(file)

            # Installed required modules and build a wheel
            os.chdir(whlsrc)
            subprocess.run(["pip3", "install", "-r", "requirements.txt"])
            subprocess.run(["python3", "setup.py", "bdist_wheel"])

            # Find the whl file in the dist folder.
            os.chdir(os.path.join(whlsrc, "dist"))
            sp = subprocess.run(["ls"], capture_output=True, text=True)
            wheel_file = None
            for file in sp.stdout.split("\n"):
                if file.endswith("whl") is True:
                    wheel_file = file
                    break
            if wheel_file is None:
                raise ValueError(f"Cannot find a whl file in the dist directory of the {whlsrc} project.")

            # Copy the whl to the lib directory
            subprocess.run(["cp", wheel_file, self.libdir])

            project_name = wheel_file[:wheel_file.index("-")]

            # Remove old versions of the wheel.
            os.chdir(self.libdir)
            for existing_whl in existing_whls:
                if existing_whl.startswith(project_name) is False:
                    continue
                if existing_whl == wheel_file:
                    continue
                os.unlink(existing_whl)

            for req in reqfiles:
                shutil.copy(req, f"{req}.bak")
                requirement_data = []
                with open(req, "r") as fh:
                    requirement_data = fh.readlines()
                    fh.close()

                pattern = re.compile(re.escape(project_name) + "-.*?.whl" )
                with open(req, "w") as fh:
                    for line in requirement_data:
                        line = re.sub(pattern, wheel_file, line)
                        fh.write(line)
                    fh.close()
                os.unlink(f"{req}.bak")

        finally:
            os.chdir(current_dir)


if __name__ == '__main__':
    setup(
        cmdclass={
            'wheel': Wheel
        }
    )
