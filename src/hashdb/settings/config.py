# HashDB
from ..types.settings import Settings


PLUGIN_SETTINGS: Settings = Settings.defaults()

# Note: hotkeys are bound to actions!
PLUGIN_HOTKEYS = {
    "lookup_hash":    "Alt+`",
    "hunt_hash_algo": None,
    "scan_hashes":    None
}

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
