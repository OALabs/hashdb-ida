# System packages/modules
import requests

# HashDB
from ..exceptions import Exceptions


def get(url: str, **kwargs) -> requests.Response:
    """
    Performs a GET request on the provided URL.
    @param url: url for the Request instance
    @param kwargs: remaining keyword arguments
    @return: a Response instance
    @raise Exceptions.Timeout: if a request timed out
    @raise Exceptions.ResponseCode: if an unexpected status code is encountered
    """
    try:
        response = requests.get(url, **kwargs)
    except requests.Timeout:
        raise Exceptions.Timeout(f"Timed out when executing a request: {url}")

    # Check if the response code was 200 OK
    if not response.ok:
        raise Exceptions.ResponseCode(f"Unexpected response code from: {url}", response_code=response.status_code)

    # Return the response
    return response


def post(url: str, **kwargs) -> requests.Response:
    """
    Performs a POST request on the provided URL.
    @param url: url for the Request instance
    @param kwargs: remaining keyword arguments
    @return: a Response instance
    @raise Exceptions.Timeout: if a request timed out
    @raise Exceptions.ResponseCode: if an unexpected status code is encountered
    """
    try:
        response = requests.post(url, **kwargs)
    except requests.Timeout:
        raise Exceptions.Timeout(f"Timed out when executing a request: {url}")

    # Check if the response code was 200 OK
    if not response.ok:
        raise Exceptions.ResponseCode(f"Unexpected response code from: {url}", response_code=response.status_code)

    # Return the response
    return response
