# System packages/modules
import os
import json

# IDAPython
import ida_netnode

# HashDB
from .plugin import PLUGIN_NAME, PLUGIN_NETNODE_ID
from ..types.settings import Settings
from ..utilities.ida import get_user_directory_path
from ..exceptions import Exceptions


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
    """
    settings_file_path = os.path.join(get_user_directory_path(), "plugins", PLUGIN_NAME, "settings.json")

    # Return the file path
    return settings_file_path


def read_settings_from_disk(file_path: str) -> Settings:
    """
    Reads settings from a file on disk.
    @param file_path: the path of the file to read from
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


def read_settings_from_database(netnode_id: str = PLUGIN_NETNODE_ID) -> Settings:
    """
    Reads settings from the database.
    @param netnode_id: the netnode id attempt to parse
    @return: a new Settings instance
    @raise Exceptions.NetnodeNotFound: if the netnode_id doesn't exist in the database
    @raise Exceptions.InvalidNetnode: if any of the elements in the netnode aren't
                                      formatted properly, don't exist, or if
                                      the settings failed to parse
    """
    netnode = ida_netnode.netnode(netnode_id)

    # Check if the netnode exists
    if not ida_netnode.exist(netnode):
        raise Exceptions.NetnodeNotFound(f"Netnode doesn't exist: {netnode_id=}")

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


def load_settings() -> Settings:
    """
    Loads settings from the database, or from the config file path.
    @raise Exceptions.LoadSettingsFailure: if any of the operations failed
    """
    # Attempt to load the settings from the database first
    try:
        return read_settings_from_database()
    except (Exceptions.NetnodeNotFound, Exceptions.InvalidNetnode):
        pass

    # Attempt to load the settings from the disk
    try:
        settings_file_path = get_settings_file_path()
        # Check if the file exists
        if not os.path.exists(settings_file_path):
            raise Exceptions.InvalidPath("Path doesn't exist.", path=settings_file_path)

        return read_settings_from_disk(settings_file_path)
    except Exceptions.InvalidPath as exception:
        raise Exceptions.LoadSettingsFailure(
            "Failed to find settings file on disk.", base_error=exception)
    except (OSError, Exceptions.Json, Exceptions.InvalidSettings) as exception:
        raise Exceptions.LoadSettingsFailure(
            "Failed to load settings from the database and disk.", base_error=exception)


def save_settings_to_disk(settings: Settings, file_path: str = get_settings_file_path()):
    """
    Saves settings to a file on disk.
    @param settings: settings to save
    @param file_path: the path of the file to save to
    @raise Exceptions.InvalidPath: if the path is a directory
    @raise OSError: if creating/opening the file/directories failed
    """
    # Check if the path provided is a directory
    if os.path.isdir(file_path):
        raise Exceptions.InvalidPath("The path provided must be a file path.", path=file_path)

    # Check if the directories exist
    parent_directories = os.path.dirname(file_path)
    if not os.path.exists(parent_directories):
        # Attempt to create the directories,
        #  this will throw an OSError if it fails
        os.makedirs(parent_directories)

    # Format the settings
    settings_dict: dict = {
        "settings": settings.to_json()
    }

    # Prevent accidentally saving the algorithm to global settings
    settings_dict["settings"]["algorithm"] = None

    # Open/create the file for writing:
    with open(file_path, "w") as file:
        json.dump(settings_dict, file, indent=2)


def save_settings_to_database(settings: Settings, netnode_id: str = PLUGIN_NETNODE_ID):
    """
    Saves the current settings to the local database.
    @param settings: settings to save
    @param netnode_id: the netnode id to save to
    @raise Exceptions.IDAPython: if the netnode id couldn't be created
    @raise SystemError: if netnode.hashset_buf failed
    """
    netnode = ida_netnode.netnode(netnode_id)

    # Create a new netnode (overwrite)
    if ida_netnode.exist(netnode):
        # Kill/delete the netnode
        netnode.kill()

        # Create the netnode
        if not netnode.create(netnode_id):
            raise Exceptions.IDAPython(f"Failed to create netnode by id: {netnode_id=}")

    # Insert the required values into the netnode
    netnode.hashset_buf("api_url", settings.api_url)
    netnode.hashset_buf("enum_prefix", settings.enum_prefix)
    netnode.hashset_buf("request_timeout", str(settings.request_timeout))

    # Check if the settings instance uses an algorithm,
    #  otherwise return
    if not settings.algorithm:
        return

    # Insert the remaining algorithm settings
    algorithm = settings.algorithm.to_json()
    netnode.hashset_buf("algorithm_algorithm", algorithm["name"])
    netnode.hashset_buf("algorithm_description", algorithm["description"])
    netnode.hashset_buf("algorithm_type", algorithm["type"])


def save_settings(settings: Settings, local: bool):
    """
    Saves settings to the database or to the settings file path.
    @param settings: settings to save
    @param local: should the settings be saved locally (in the database)
                  or globally (in the file)
    @raise Exceptions.SaveSettingsFailure: if we failed to save the settings
    """
    if local:
        try:
            # Try to save the settings to the database
            save_settings_to_database(settings)
        except (Exceptions.IDAPython, SystemError) as exception:
            raise Exceptions.SaveSettingsFailure(
                "Failed to save the settings to the database.", base_error=exception)
    else:
        try:
            # Try to save the settings to a file
            save_settings_to_disk(settings)
        except (Exceptions.InvalidPath, OSError) as exception:
            raise Exceptions.SaveSettingsFailure(
                "Failed to save the settings to a file.", base_error=exception)
