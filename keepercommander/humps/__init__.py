# -*- coding: utf-8 -*-
# flake8: noqa
# noreorder
"""
Underscore-to-camelCase converter (and vice versa) for strings and dict keys in Python.
"""
__title__ = "pyhumps"
__version__ = "1.6.1"
__author__ = "Nick Ficano"
__license__ = "MIT License"
__copyright__ = "Copyright 2019 Nick Ficano"

from .humps import decamelize, depascalize

__all__ = ['decamelize', 'depascalize']