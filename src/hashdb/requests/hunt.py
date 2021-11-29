# System packages/modules
import json

# HashDB
from ..utilities.requests import post as post_request
from ..exceptions import Exceptions
from ..types.hit import Hit


def fetch(api_url: str, timeout: int,
          hash_value: int) -> dict:
    """
    Fetches all hash matches/hits from the server.
    @param api_url: api url to use
    @param timeout: amount of seconds before we timeout
    @param hash_value: integer value of a hash
    @return: a json object (dict) fetched from the server
             containing a list of hits
    @raise Exceptions.Timeout: if a request timed out
    @raise Exceptions.ResponseCode: if an unexpected status code is encountered,
    @raise Exceptions.Json: if the response body isn't valid JSON.
    """
    # Perform the request
    url = f"{api_url}/hunt"
    response = post_request(url, json={"hashes": [hash_value]}, timeout=timeout)

    # Convert and return the results
    try:
        return response.json()
    except json.JSONDecodeError:
        raise Exceptions.Json(f"Invalid response body from: {url}, body={response.text}")


def format_response(response_data: dict) -> tuple[Hit, ...]:
    """
    Formats the raw json response into a list of hash algorithms.
    @param response_data: a json object
    @return: a list of Hit instances
    """
    # Parse the hash algorithms
    hits: list[Hit] = []

    hit: dict
    # Iterate the algorithms
    for hit in response_data.get("hits", []):
        # Append the name if it doesn't already exist
        hits.append(Hit.from_json(hit))

    # Return the list of hash algorithms
    return tuple(hits)
