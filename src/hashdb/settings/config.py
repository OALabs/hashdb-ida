# System packages/modules
import os
import json

# IDAPython
import ida_netnode

# HashDB
from .plugin import PLUGIN_NETNODE_ID
from ..types.settings import Settings
from ..utilities.ida import get_user_directory_path
from ..exceptions import Exceptions


PLUGIN_SETTINGS: Settings = Settings.defaults()

# Note: hotkeys are bound to actions!
PLUGIN_HOTKEYS = {
    "lookup_hash":    "Alt+`",
    "hunt_hash_algo": None,
    "scan_hashes":    None
}


def get_settings_file_path() -> str:
    """
    Fetches the path of the settings/config file.
    @return: a path on disk
    @raise Exceptions.InvalidPath: if the file doesn't exist
    """
    settings_file_path = os.path.join(get_user_directory_path(), "plugins", "HashDB", "settings.json")

    # Check if the file exists
    if not os.path.exists(settings_file_path):
        raise Exceptions.InvalidPath("Path doesn't exist.", path=settings_file_path)

    # Return the file path
    return settings_file_path


def read_settings_from_disk(file_path: str) -> Settings:
    """
    Reads settings from a file path.
    @param file_path: the file path
    @return: a new Settings instance
    @raise OSError: if opening the file failed
    @raise Exceptions.Json: if the data in the file isn't valid JSON
    @raise Exceptions.InvalidSettings: if parsing the settings failed
    """
    try:
        # Try to open the file and parse the JSON
        with open(file_path) as file:
            json_data = json.load(file)

            # Parse and save the settings
            return Settings.from_json(json_data["settings"])
    except json.JSONDecodeError:
        raise Exceptions.Json(f"Invalid JSON data in file: {file_path=}")


def read_settings_from_database(netnode_id: str) -> Settings:
    """
    Reads settings from the database.
    @param netnode_id: the netnode id attempt to parse
    @return: a new Settings instance
    @raise Exceptions.NetnodeNotFound: if the netnode_id doesn't exist in the database
    @raise Exceptions.InvalidNetnode: if any of the elements in the netnode aren't
                                      formatted properly, don't exist, or if
                                      the settings failed to parse
    """
    # Check if the netnode exists
    if not ida_netnode.exist(netnode_id):
        raise Exceptions.NetnodeNotFound(f"Netnode doesn't exist: {netnode_id=}")

    netnode = ida_netnode.netnode(netnode_id)

    # Get the required netnode values
    api_url: str = netnode.hashstr("api_url")
    enum_prefix: str = netnode.hashstr("enum_prefix")
    try:
        request_timeout: int = int(netnode.hashstr("request_timeout"))
    except ValueError as exception:
        raise Exceptions.InvalidNetnode(f"Invalid request timeout: {exception=}")

    # Make sure the settings values exist
    if not api_url or not enum_prefix or not request_timeout:
        raise Exceptions.InvalidNetnode(
            f"Invalid netnode settings: {api_url=}, {enum_prefix=}, {request_timeout=}")

    settings_dict: dict = {
        "api_url": api_url,
        "enum_prefix": enum_prefix,
        "request_timeout": request_timeout,
        "algorithm": None
    }

    algorithm_name: str = netnode.hashstr("algorithm_algorithm")
    algorithm_description: str = netnode.hashstr("algorithm_description")
    algorithm_type: str = netnode.hashstr("algorithm_type")

    # If one of the values above are empty/don't exist,
    #  attempt parse and the settings
    if not algorithm_name or not algorithm_description or not algorithm_type:
        try:
            # Try to parse the settings
            return Settings.from_json(settings_dict)
        except Exceptions.InvalidSettings as exception:
            raise Exceptions.InvalidNetnode(
                f"Invalid netnode settings when parsing: {exception.settings_object=}")

    # Otherwise, construct the algorithm dict and
    #  attempt to parse the settings
    settings_dict["algorithm"] = {
        "algorithm": algorithm_name,
        "description": algorithm_description,
        "type": algorithm_type
    }

    try:
        # Try to parse the settings
        return Settings.from_json(settings_dict)
    except Exceptions.InvalidSettings as exception:
        raise Exceptions.InvalidNetnode(
            f"Invalid netnode settings when parsing: {exception.settings_object=}")


def load_settings():
    """
    Loads settings from the database, or from the config file path.
    @raise Exceptions.LoadSettingsFailure: if any of the operations failed
    """
    global PLUGIN_SETTINGS

    # Attempt to load the settings from the database first
    try:
        PLUGIN_SETTINGS = read_settings_from_database(PLUGIN_NETNODE_ID)
    except (Exceptions.NetnodeNotFound, Exceptions.InvalidNetnode):
        pass

    # Attempt to load the settings from the disk
    try:
        settings_path = get_settings_file_path()
        PLUGIN_SETTINGS = read_settings_from_disk(settings_path)
    except Exceptions.InvalidPath as exception:
        raise Exceptions.LoadSettingsFailure(
            f"Failed to find settings file on disk: {exception=}")
    except (OSError, Exceptions.Json, Exceptions.InvalidSettings) as exception:
        raise Exceptions.LoadSettingsFailure(
            f"Failed to load settings from the netnode and disk: {exception=}")


# TODO (printup): move these TODOs to git issues :)

# TODO (printup): the default API_URL should be modifiable by the user
#                 the user should have an option to be able to set it,
#                 at which point the API_URL would be saved in a global
#                 config file with the following API:
#                 ida_diskio.get_user_idadir
# TODO (printup): the same applies for the ENUM_PREFIX and REQUEST_TIMEOUT
# TODO (printup): all of these variables should also be savable locally,
#                 which would be the preferred way (higher priority) of
#                 fetching user settings
