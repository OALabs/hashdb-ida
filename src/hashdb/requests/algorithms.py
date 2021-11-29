# System packages/modules
import json

# HashDB
from ..utilities.requests import get as get_request
from ..exceptions import Exceptions
from ..types.algorithm import Algorithm


def fetch(api_url: str, timeout: int) -> dict:
    """
    Fetches all of the algorithms from the server.
    @param api_url: api url to use
    @param timeout: amount of seconds before we timeout
    @return: a json object (dict) fetched from the server
             containing data about each algorithm
    @raise Exceptions.Timeout: if a request timed out
    @raise Exceptions.ResponseCode: if an unexpected status code is encountered
    @raise Exceptions.Json: if the response body isn't valid JSON.
    """
    # Perform the request
    url = f"{api_url}/hash"
    response = get_request(url, timeout=timeout)

    # Convert and return the results
    try:
        return response.json()
    except json.JSONDecodeError:
        raise Exceptions.Json(f"Invalid response body from: {url}, body={response.text}")


def format_response(response_data: dict) -> tuple[Algorithm, ...]:
    """
    Formats the raw json response into friendly structures.
    @param response_data: a json object
    @return: a list of Algorithm instances
    @raise Exceptions.InvalidAlgorithm: if any of the required keys are missing
    @raise Exceptions.UnknownAlgorithmType: if an unknown algorithm type is encountered
    """
    # Parse the algorithms
    algorithms: list[Algorithm] = []

    algorithm: dict
    # Iterate the algorithms
    for algorithm in response_data.get("algorithms", []):
        # Append an Algorithm instance
        algorithms.append(Algorithm.from_json(algorithm))

    # Return the list of Algorithm instances
    return tuple(algorithms)
