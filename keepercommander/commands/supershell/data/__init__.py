"""
SuperShell data loading

Functions for loading vault data, building trees, and searching.
"""

from .vault_loader import load_vault_data
from .search import (
    search_records,
    filter_records_by_folder,
    get_root_records,
    count_records_in_folder,
)

__all__ = [
    'load_vault_data',
    'search_records',
    'filter_records_by_folder',
    'get_root_records',
    'count_records_in_folder',
]
