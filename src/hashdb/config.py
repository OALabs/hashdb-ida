# noinspection SpellCheckingInspection
AUTHOR: str = "Sergei Frankoff"
VERSION: tuple = (2, 0, 0)  # major, minor, micro
VERSION_STRING: str = ".".join([str(element) for element in VERSION])
PLUGIN_NAME: str = "HashDB"
PLUGIN_DEFAULT_SETTINGS = {
    "API_URL":         "https://hashdb.openanalysis.net",
    "NETNODE_ID":      "$hashdb",  # unique netnode ID for database specific settings
    "ENUM_PREFIX":     "hashdb_strings",
    "REQUEST_TIMEOUT": 15  # in seconds
}

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
