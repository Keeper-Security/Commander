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

from keepercommander.plugins.humps.humps import camelize
from keepercommander.plugins.humps.humps import decamelize
from keepercommander.plugins.humps.humps import depascalize
from keepercommander.plugins.humps.humps import pascalize

from keepercommander.plugins.humps.humps import is_camelcase
from keepercommander.plugins.humps.humps import is_pascalcase
from keepercommander.plugins.humps.humps import is_snakecase