"""
Integer pool for reusing stream indices.

This module provides the IntegerPool class for efficiently managing
integer indices that can be acquired and released.
"""

from typing import List


class IntegerPool:
    """
    Integer pool that returns consistently increasing integers while in use,
    and previously-used integers when possible.

    This is used by the Guacamole client for managing stream indices,
    allowing freed indices to be reused to conserve the index space.

    Example:
        pool = IntegerPool()
        idx1 = pool.next()  # Returns 0
        idx2 = pool.next()  # Returns 1
        pool.free(idx1)     # Release index 0
        idx3 = pool.next()  # Returns 0 (reused)
        idx4 = pool.next()  # Returns 2

    Attributes:
        next_int: The next integer to return if no freed integers are available.
    """

    def __init__(self):
        """Initialize a new IntegerPool."""
        self._pool: List[int] = []
        self.next_int: int = 0

    def next(self) -> int:
        """
        Return the next available integer from the pool.

        If previously freed integers exist, one of those is returned.
        Otherwise, a new integer is allocated and returned.

        Returns:
            The next available integer.
        """
        if self._pool:
            return self._pool.pop(0)
        result = self.next_int
        self.next_int += 1
        return result

    def free(self, integer: int) -> None:
        """
        Free the given integer, allowing it to be reused.

        Args:
            integer: The integer to free.
        """
        self._pool.append(integer)

    def __contains__(self, integer: int) -> bool:
        """
        Check if an integer is currently in the free pool.

        Args:
            integer: The integer to check.

        Returns:
            True if the integer is in the free pool, False otherwise.
        """
        return integer in self._pool
