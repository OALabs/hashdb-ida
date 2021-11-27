# System packages/modules
import json

# HashDB
from ..utilities.requests import get as get_request
from ..exceptions import Exceptions
from ..types.hash import Hash


def fetch(api_url: str, timeout: int,
          module_name: str, algorithm_name: str, permutation_type: str) -> dict:
    """
    Fetches all hash matches/hits from the server.
    @param api_url: api url to use
    @param timeout: amount of seconds before we timeout
    @param module_name: name of the module
    @param algorithm_name: name of the algorithm
    @param permutation_type: permutation type
    @return: a json object (dict) fetched from the server
             containing a list of hash objects
    @raise Exceptions.Timeout: if a request timed out
    @raise Exceptions.ResponseCode: if an unexpected status code is encountered,
    @raise Exceptions.Json: if the response body isn't valid JSON.
    """
    # Perform the request
    url = f"{api_url}/module/{module_name}/{algorithm_name}/{permutation_type}"
    response = get_request(url, timeout=timeout)

    # Convert and return the results
    try:
        return response.json()
    except json.JSONDecodeError:
        raise Exceptions.Json(f"Invalid response body from: {url}, body={response.text}")
    pass


def format_response(response_data: dict) -> list[Hash]:
    """
    Formats the raw json response into a list of Hash instances.
    @param response_data: a json object
    @return: a list of Hash instances
    @raise Exceptions.InvalidHashObject: if a hash object is missing
                                         the "string" object
    """
    # Parse the hashes
    hashes = []

    hash: dict
    # Iterate the algorithms
    for hash in response_data.get("hashes", []):
        value: int = hash.get("hash")
        string_object: dict = hash.get("string")

        # Check if the string object is valid
        if not string_object:
            raise Exceptions.InvalidHashObject("\"string\" object doesn't exist, or is empty.", hash_object=hash)

        string: str = string_object.get("string")
        is_api: bool = string_object.get("is_api")

        # If the hash is not an API, append a Hash instance,
        #  and skip resolving other properties:
        if not is_api:
            hashes.append(Hash(value=value, string=string, is_api=is_api))
            continue

        # Resolve the remaining properties
        permutation_type: str = string_object.get("permutation")
        api: str = string_object.get("api")
        modules: list = string_object.get("modules")

        # Append a Hash instance
        hashes.append(Hash(value=value, string=string, is_api=is_api,
                           permutation_type=permutation_type, api=api,
                           modules=tuple(modules)))

    # Return the list of hashes
    return hashes
