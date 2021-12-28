Commander support for Keepass files
---

If you plan to use the Keepass import/export features, you need to manually install the pykeepass module.

```bash
$ pip3 install pykeepass
```

The above-mentioned command might fail installing the **lxml** package, especially on Microsoft Windows.
In this case you need to install the pre-compiled binary version of **lxml** package.

You can find pre-compiled lxml binary packages for your platform from [PyPI](https://pypi.org/project/lxml/#files).

Alternatively, for Windows platform you can download binary packages from Christoph Gohlke's [Unofficial Windows Binaries](https://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml) website. First you need to get the version of your Python interpreter and the Python platform installed:

```bash
$ python3 --version
$ python3 -c "import distutils.util; print(distutils.util.get_platform())"
```

For example:
```
$ python3 --version
Python 3.6.0

$ python3 -c "import distutils.util; print(distutils.util.get_platform())"
Win32
```

In this example, the lxml package to download is ```lxml-4.2.3-cp36-cp36m-win32.whl```

Once you download the correct .whl file from the site, you can install the lxml package like this: 

```bash
$ pip3 install lxml-4.2.3-cp36-cp36m-win32.whl
```

Then complete installation of pykeepass:
```bash
$ pip3 install pykeepass
```

Now you can use the ```import --format=keepass``` and ```export --format=keepass``` commands within Keeper Commander.
