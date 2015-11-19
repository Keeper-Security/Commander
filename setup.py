#!/usr/bin/env python

from setuptools import setup

from os import path

LICENSE = open("LICENSE").read()

# strip links from the descripton on the PyPI
here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

install_requires = [
    'colorama',
    'pycrypto',
    'requests',
    'tabulate'
]

setup(name='keepercommander',
      version='0.2.6',
      description='Keeper Commander for Python 3',
      long_description=long_description,
      author='Craig Lurey',
      author_email='craig@keepersecurity.com',
      url='https://github.com/Keeper-Security/Commander',
      license=LICENSE,
      classifiers=["Development Status :: 4 - Beta",
                   "License :: OSI Approved :: MIT License",
                   "Operating System :: OS Independent",
                   "Programming Language :: Python :: 3.4",
                   "Topic :: Security"],
      keywords='security password',

      packages=['keepercommander'],

      entry_points={
          "console_scripts": [
              "keeper=keepercommander:main",
          ],
      },
      install_requires=install_requires
      )
