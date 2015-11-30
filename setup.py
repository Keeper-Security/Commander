from setuptools import setup
from pypandoc import convert

install_requires = [
    'colorama',
    'pycrypto',
    'requests',
    'tabulate'
]

setup(name='keepercommander',
      version='0.3.0',
      description='Keeper Commander for Python 3',
      long_description=convert('README.md', 'rst'),
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

      packages=['keepercommander'],

      entry_points={
          "console_scripts": [
              "keeper=keepercommander:main",
          ],
      },
      install_requires=install_requires
      )
