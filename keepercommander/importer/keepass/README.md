Commander support for Keepass files
---

If you plan to use the Keepass import/export features, you need to manually install the libkeepass module.

```bash
$ pip3 install libkeepass
```

The above-mentioned command might fail installing the **lxml** package, especially on Microsoft Windows.
In this case you need to install the pre-compiled binary version of **lxml** package.

You can find pre-compiled lxml binary packages for your platform from [PyPI](https://pypi.org/project/lxml/#files).

Alternatively, for Windows platform you can download binary packages from Christoph Gohlke's [Unofficial Windows Binaries](https://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml) website.

Instructions for selecting the correct package:

* Get the version of your Python interpreter:
```bash
$ python3 --version
```

...and the Python platform:
```bash
python3 -c "import distutils.util; print(distutils.util.get_platform())"
```

For example:
```
Python Version: Python 3.6.0
Python Platform: Win32
```
The lxml package to download is ```lxml-4.2.3-cp36-cp36m-win32.whl```

Another example:
```
Python Version: Python 3.5.0
Python Platform: win-amd64
```
The lxml package to download is ```lxml-4.2.3-cp35-cp35m-win-amd64.whl```

Once you download the correct .whl file from the site, you can install the package like this: 

```bash
$ pip3 install lxml-4.2.3-cp36-cp36m-win32.whl
$ pip3 install libkeepass```
```

After installation is complete, you can use the ```import --format=keepass``` and ```export --format=keepass``` commands.

