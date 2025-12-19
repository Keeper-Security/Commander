"""
Guacamole event system.

This module provides the Event and EventTarget classes for implementing
event-driven architecture in Guacamole applications.
"""

import time
from typing import Any, Callable, Dict, List, Optional


class Event:
    """
    An arbitrary event that can be dispatched by an EventTarget.

    This class serves as the base for more specific event types. Each event
    has a type name and timestamp.

    Attributes:
        type: The unique name of this event type.
        timestamp: Timestamp in seconds when this event was created.

    Example:
        event = Event("connection_state_changed")
        print(f"Event type: {event.type}")
        print(f"Age: {event.get_age()} seconds")
    """

    def __init__(self, event_type: str):
        """
        Initialize a new Event.

        Args:
            event_type: The unique name of this event type.
        """
        self.type: str = event_type
        self.timestamp: float = time.time()

    def get_age(self) -> float:
        """
        Return the number of seconds elapsed since this event was created.

        Returns:
            The age of this event in seconds.
        """
        return time.time() - self.timestamp

    def invoke_legacy_handler(self, target: 'EventTarget') -> None:
        """
        Invoke the legacy event handler associated with this event.

        This method is called automatically by EventTarget.dispatch() and
        provides backward compatibility with single-handler patterns like
        "onmousedown" or "onkeyup".

        Subclasses should override this method to invoke the appropriate
        legacy handler on the target.

        Args:
            target: The EventTarget that emitted this event.
        """
        # Default implementation does nothing
        pass


class EventTarget:
    """
    An object that can dispatch Event objects to registered listeners.

    Listeners registered with on() are automatically invoked based on the
    event type when dispatch() is called. This class is typically subclassed
    by objects that need to emit events.

    Example:
        target = EventTarget()

        def on_state_change(event, source):
            print(f"State changed: {event.type}")

        target.on("state_change", on_state_change)
        target.dispatch(Event("state_change"))
    """

    # Type alias for listener callbacks
    Listener = Callable[['Event', 'EventTarget'], None]

    def __init__(self):
        """Initialize a new EventTarget."""
        self._listeners: Dict[str, List[EventTarget.Listener]] = {}

    def on(self, event_type: str, listener: 'EventTarget.Listener') -> None:
        """
        Register a listener for events of the given type.

        Args:
            event_type: The unique name of the event type to listen for.
            listener: The callback function to invoke when an event of this
                type is dispatched. The function receives the Event object
                and the dispatching EventTarget.
        """
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(listener)

    def on_each(self, types: List[str], listener: 'EventTarget.Listener') -> None:
        """
        Register a listener for multiple event types.

        This is equivalent to calling on() for each type in the list.

        Args:
            types: List of event type names to listen for.
            listener: The callback function to invoke for any of these events.
        """
        for event_type in types:
            self.on(event_type, listener)

    def off(self, event_type: str, listener: 'EventTarget.Listener') -> bool:
        """
        Unregister a previously registered listener.

        If the same listener was registered multiple times, only the first
        occurrence is removed.

        Args:
            event_type: The event type the listener was registered for.
            listener: The listener function to remove.

        Returns:
            True if the listener was found and removed, False otherwise.
        """
        if event_type not in self._listeners:
            return False

        listeners = self._listeners[event_type]
        for i, registered_listener in enumerate(listeners):
            if registered_listener is listener:
                listeners.pop(i)
                return True

        return False

    def off_each(self, types: List[str], listener: 'EventTarget.Listener') -> bool:
        """
        Unregister a listener from multiple event types.

        This is equivalent to calling off() for each type in the list.

        Args:
            types: List of event type names to unregister from.
            listener: The listener function to remove.

        Returns:
            True if the listener was removed from at least one event type.
        """
        changed = False
        for event_type in types:
            if self.off(event_type, listener):
                changed = True
        return changed

    def dispatch(self, event: Event) -> None:
        """
        Dispatch an event to all registered listeners.

        First invokes the legacy handler (if the event supports it), then
        invokes all listeners registered for this event type.

        Args:
            event: The event to dispatch.
        """
        # Invoke legacy handler for backward compatibility
        event.invoke_legacy_handler(self)

        # Invoke all registered listeners
        listeners = self._listeners.get(event.type)
        if listeners:
            for listener in listeners:
                listener(event, self)
