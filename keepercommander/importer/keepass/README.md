Commander support for Keepass files
---

1. Install libkeepass module

```
pip3 install libkeepass
```

The above-mentioned command might fail installing **lxml** package. Especially on MS Windows platform.<br> 
In this case you may want to install pre-compiled binary version of **lxml** package.<br>

**lxml** is high performance XML manipulation library. Library site: https://lxml.de/

You can find pre-compiled binary packages for your platform from [PyPI](https://pypi.org/project/lxml/#description) 
site download section. <br>
Alternatively for Windows platform, you can download binary package from 
Christoph Gohlke's [Unofficial Windows Binaries](https://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml) website.
<br><br>
Get the version of Python interpreter:<br>
```python3 --version```<br>
and the Python platform <br>
```python3 -c "import distutils.util; print(distutils.util.get_platform())"```<br>

For instance:<br>
Python Version: ```Python 3.6.0```<br>
Python Platform: ```Win32```<br>
**lxml** binary package name: ```lxml-4.2.3-cp36-cp36m-win32.whl```

Python Version: ```Python 3.5.0```<br>
Python Platform: ```win-amd64```<br>
**lxml** binary package name: ```lxml-4.2.3-cp35-cp35m-win-amd64.whl```

Download binary package and install it with **pip3**

```pip3 install lxml-4.2.3-cp36-cp36m-win32.whl```<br>
then<br>
```pip3 install libkeepass```


2. Import your data from Keepass file

```
keeper import --format=keepass <keepass_file>.kdbx
```