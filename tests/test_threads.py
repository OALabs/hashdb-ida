import pytest

import threading
from hashdb.utilities.threads import Worker


def raise_exception():
    """Used for testing error_callback behavior."""
    raise Exception


def test_missing_arguments():
    """Simulate missing `target` argument."""
    with pytest.raises(TypeError):
        # noinspection PyArgumentList
        Worker()


def test_done_callback_without_results():
    """Test if the `done_callback` handler is properly executed without results."""
    was_done_executed = False

    def done_callback():
        nonlocal was_done_executed
        was_done_executed = True

    worker = Worker(target=lambda _=None: None, done_callback=done_callback)
    worker.start()
    worker.join()

    assert was_done_executed


def test_done_callback_with_single_result():
    """Test if the `done_callback` handler is properly executed with a single result."""
    was_done_executed = False

    # noinspection PyUnusedLocal
    def done_callback(integer: int):
        assert integer == 1

        nonlocal was_done_executed
        was_done_executed = True

    worker = Worker(target=lambda _=None: 1, done_callback=done_callback)
    worker.start()
    worker.join()

    assert was_done_executed


def test_done_callback_with_multiple_results():
    """Test if the `done_callback` handler is properly executed with multiple result."""
    was_done_executed = False

    # noinspection PyUnusedLocal
    def done_callback(integer: int, string: str):
        assert integer == 1
        assert string == "test"

        nonlocal was_done_executed
        was_done_executed = True

    worker = Worker(target=lambda _=None: (1, "test"), done_callback=done_callback)
    worker.start()
    worker.join()

    assert was_done_executed


def test_error_handler_no_arguments():
    """Test if the `error_callback` handler is properly executed without arguments."""
    was_error_executed = False

    def error_callback():
        nonlocal was_error_executed
        was_error_executed = True

    worker = Worker(target=raise_exception, error_callback=error_callback)
    worker.start()
    worker.join()

    assert was_error_executed


def test_error_handler_with_arguments():
    """Test if the `error_callback` handler is properly executed with arguments."""
    was_error_executed = False

    # noinspection PyUnusedLocal
    def error_callback(exception: Exception):
        nonlocal was_error_executed
        was_error_executed = True

    worker = Worker(target=raise_exception, error_callback=error_callback)
    worker.start()
    worker.join()

    assert was_error_executed


def test_expect_error():
    """Test if an exception is raised if an `error_callback` handler isn't provided."""
    # Setup exception handling
    was_exception_thrown = False

    # noinspection PyUnusedLocal
    def exception_hook(args):
        nonlocal was_exception_thrown
        was_exception_thrown = True
    threading.excepthook = exception_hook

    worker = Worker(target=raise_exception)
    worker.start()
    worker.join()

    assert was_exception_thrown
