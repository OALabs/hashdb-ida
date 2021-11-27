# System packages/modules
from dataclasses import dataclass


class Exceptions:
    """
    This class is used as a namespace for the actual
      exception objects.
    """
    class Error(Exception):
        """
        Used for general/non-specific errors.
        """

    class Json(Error):
        """
        Used when the response body
          has an invalid json format.
        """

    class ResponseCode(Error):
        """
        Used when a response status code
          isn't equal to 200 (OK)
        """
        response_code: int

        def __init__(self, message: str, response_code: int):
            super().__init__(message)
            self.response_code = response_code

    class Timeout(Error):
        """
        Used when a timeout is reached.
        """

    @dataclass
    class UnknownAlgorithmType(Error):
        """
        Used when an algorithm has an
          invalid size.
        """
        message: str
        algorithm_type: str

    @dataclass
    class InvalidHashObject(Error):
        """
        Used when a hash object wasn't
          formatted properly by the server.
        """
        message: str
        hash_object: dict
