from setuptools import setup
from os import path

import keepercommander

here = path.abspath(path.dirname(__file__))

# Get the long description from the README.md file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

install_requires = [
    'colorama',
    'pycryptodomex>=3.7.2',
    'libkeepass',
    'requests',
    'tabulate',
    'prompt_toolkit>=2.0.4',
    'asciitree',
    'protobuf>=3.6.0',
    'pyperclip'
]

setup(name='keepercommander',
      version=keepercommander.__version__,
      description='Keeper Commander for Python 3',
      long_description=long_description,
      long_description_content_type="text/markdown",
      author='Craig Lurey',
      author_email='craig@keepersecurity.com',
      url='https://github.com/Keeper-Security/Commander',
      license='MIT',
      classifiers=["Development Status :: 4 - Beta",
                   "License :: OSI Approved :: MIT License",
                   "Operating System :: OS Independent",
                   "Programming Language :: Python :: 3.4",
                   "Topic :: Security"],
      keywords='security password',

      packages=['keepercommander',
                'keepercommander.commands',
                'keepercommander.importer',
                'keepercommander.importer.json',
                'keepercommander.importer.csv',
                'keepercommander.importer.keepass',
                'keepercommander.plugins',
                'keepercommander.plugins.adpasswd',
                'keepercommander.plugins.awskey',
                'keepercommander.plugins.mssql',
                'keepercommander.plugins.mysql',
                'keepercommander.plugins.oracle',
                'keepercommander.plugins.postgresql',
                'keepercommander.plugins.ssh',
                'keepercommander.plugins.sshkey',
                'keepercommander.plugins.unixpasswd',
                'keepercommander.plugins.windows',
                'keepercommander.plugins.pspasswd',
                'keepercommander.yubikey',
                ],
      include_package_data=True,
      python_requires='>=3.4',
      entry_points={
          "console_scripts": [
              "keeper=keepercommander.__main__:main",
          ],
      },
      install_requires=install_requires
      )
