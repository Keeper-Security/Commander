"""
SelectionState - Current selection state

Contains the currently selected record/folder and pre-search state.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class SelectionState:
    """Selection state for SuperShell.

    Tracks what record or folder is currently selected,
    and preserves pre-search selection for restoration.
    """

    # Current selection
    current_folder: Optional[str] = None
    """Currently displayed folder UID"""

    selected_record: Optional[str] = None
    """Currently selected record UID"""

    selected_folder: Optional[str] = None
    """Currently selected folder UID (when a folder is selected, not a record)"""

    # Pre-search state (for restoration when search is cancelled)
    pre_search_selected_record: Optional[str] = None
    """Record that was selected before search started"""

    pre_search_selected_folder: Optional[str] = None
    """Folder that was selected before search started"""

    def has_record_selected(self) -> bool:
        """Check if a record is currently selected."""
        return self.selected_record is not None

    def has_folder_selected(self) -> bool:
        """Check if a folder is currently selected."""
        return self.selected_folder is not None

    def has_selection(self) -> bool:
        """Check if anything is selected."""
        return self.has_record_selected() or self.has_folder_selected()

    def save_for_search(self) -> 'SelectionState':
        """Return a new state with current selection saved for search restoration."""
        return SelectionState(
            current_folder=self.current_folder,
            selected_record=self.selected_record,
            selected_folder=self.selected_folder,
            pre_search_selected_record=self.selected_record,
            pre_search_selected_folder=self.selected_folder,
        )

    def restore_from_search(self) -> 'SelectionState':
        """Return a new state with pre-search selection restored."""
        return SelectionState(
            current_folder=self.current_folder,
            selected_record=self.pre_search_selected_record,
            selected_folder=self.pre_search_selected_folder,
            pre_search_selected_record=None,
            pre_search_selected_folder=None,
        )

    def select_record(self, record_uid: str) -> 'SelectionState':
        """Return a new state with the given record selected."""
        return SelectionState(
            current_folder=self.current_folder,
            selected_record=record_uid,
            selected_folder=None,
            pre_search_selected_record=self.pre_search_selected_record,
            pre_search_selected_folder=self.pre_search_selected_folder,
        )

    def select_folder(self, folder_uid: str) -> 'SelectionState':
        """Return a new state with the given folder selected."""
        return SelectionState(
            current_folder=self.current_folder,
            selected_record=None,
            selected_folder=folder_uid,
            pre_search_selected_record=self.pre_search_selected_record,
            pre_search_selected_folder=self.pre_search_selected_folder,
        )

    def clear_selection(self) -> 'SelectionState':
        """Return a new state with selection cleared."""
        return SelectionState(
            current_folder=self.current_folder,
            selected_record=None,
            selected_folder=None,
            pre_search_selected_record=self.pre_search_selected_record,
            pre_search_selected_folder=self.pre_search_selected_folder,
        )
