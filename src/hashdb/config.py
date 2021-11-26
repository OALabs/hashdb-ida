# noinspection SpellCheckingInspection
AUTHOR: str = "Sergei Frankoff"
VERSION: tuple = (2, 0, 0)  # major, minor, micro
VERSION_STRING: str = ".".join([str(element) for element in VERSION])
PLUGIN_NAME: str = "HashDB"
PLUGIN_SETTINGS = {
    "API_URL":         "https://hashdb.openanalysis.net",  # local, global
    "ENUM_PREFIX":     "hashdb_strings",                   # local, global
    "REQUEST_TIMEOUT": 15,    # in seconds                 # local, global
    "ALGORITHM":       None,  # algorithm name             # local
    "ALGORITHM_SIZE":  0,     # algorithm size             # local
}
# Note: hotkeys are bound to actions!
PLUGIN_HOTKEYS = {
    "lookup_hash":    "Alt+`",
    "hunt_hash_algo": None,
    "scan_hashes":    None
}
PLUGIN_NETNODE_ID: str = "$hashdb"     # unique netnode ID for database specific settings
PLUGIN_ACTIONS_PREFIX: str = "hashdb"  # prefixed to all actions (popup menu)

# TODO (printup): move these TODOs to git issues :)

# TODO (printup): the default API_URL should be modifiable by the user
#                 the user should have an option to be able to set it,
#                 at which point the API_URL would be saved in a global
#                 config file (IDA directory, or appdata (system support
#                 funkiness)?
# TODO (printup): the same applies for the ENUM_PREFIX and REQUEST_TIMEOUT
# TODO (printup): all of these variables should also be savable locally,
#                 which would be the preferred way (higher priority) of
#                 fetching user settings
