# System packages/modules
import inspect
from typing import Callable
from dataclasses import dataclass
from threading import Thread


@dataclass(unsafe_hash=True)
class Worker(Thread):
    """The worker implementation for multi-threading support."""
    target: Callable
    done_callback: Callable = None
    error_callback: Callable = None

    def __post_init__(self):
        """Required to initialize the base class (Thread)."""
        super().__init__(target=self.__wrapped_target, daemon=True)

    def __wrapped_target(self, *args, **kwargs):
        """
        Wraps the target function to allow callbacks and error handling.
        @raise Exception: if an unhandled exception is encountered it will
                          be raised
        """
        try:
            # Execute the target
            results = self.target(*args, **kwargs)

            # Execute the done callback, if it exists
            if self.done_callback is not None:
                # Call the function based on the amount of arguments it expects
                argument_spec = inspect.getfullargspec(self.done_callback)
                argument_count = len(argument_spec.args)

                if argument_count > 1:
                    self.done_callback(*results)
                elif argument_count == 1 and results is not None:
                    self.done_callback(results)
                else:
                    self.done_callback()
        except Exception as exception:
            # Execute the error callback, if it exits;
            #  otherwise raise the exception (unhandled)
            if self.error_callback is not None:
                # Call the function based on the amount of arguments it expects
                argument_spec = inspect.getfullargspec(self.error_callback)
                argument_count = len(argument_spec.args)

                if argument_count == 1:
                    self.error_callback(exception)
                else:
                    self.error_callback()
            else:
                raise exception
        finally:
            # Cleanup the callbacks (decrease reference counts)
            if self.done_callback is not None:
                del self.done_callback
            if self.error_callback is not None:
                del self.error_callback
