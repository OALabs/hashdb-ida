# System packages/modules
import json
import requests

# HashDB
from ..exceptions import Exceptions


def fetch(api_url: str, timeout: int, hash_value: int) -> dict:
    """
    Fetches all hash matches/hits from the server.
    @param api_url: api url to use
    @param timeout: amount of seconds before we timeout
    @param hash_value: integer value of a hash
    @return: a json object (dict) fetched from the server
             containing a list of hash algorithms
    @raise Exceptions.Timeout: if a request timed out
    @raise Exceptions.ResponseCode: if an unexpected status code is encountered,
    @raise Exceptions.Json: if the response body isn't valid JSON.
    """
    # Perform the request
    url = f"{api_url}/hunt"
    try:
        response = requests.post(url, json={"hashes": [hash_value]}, timeout=timeout)
    except requests.Timeout:
        raise Exceptions.Timeout(f"Timed out when executing a request: {url}")

    # Check if the response code was 200 OK
    if not response.ok:
        raise Exceptions.ResponseCode(f"Unexpected response code from: {url}", response_code=response.status_code)

    # Convert and return the results
    try:
        return response.json()
    except json.JSONDecodeError:
        raise Exceptions.Json(f"Invalid response body from: {url}, body={response.text}")


def format_response(response_data: dict) -> list[str]:
    """
    Formats the raw json response into a list of hash algorithms.
    @param response_data: a json
    @return: a list of Algorithm instances
    @raise Exceptions.UnknownAlgorithmType: if an unknown algorithm type is encountered
    """
    # Parse the hash algorithms
    algorithms = []

    algorithm: dict
    # Iterate the algorithms
    for algorithm in response_data.get("hits", []):
        name = algorithm.get("algorithm")

        # Append the name if it doesn't already exist
        if name not in algorithms:
            algorithms.append(name)

    # Return the list of hash algorithms
    return algorithms
