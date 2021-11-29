# noinspection SpellCheckingInspection
AUTHOR: str = "Sergei Frankoff (herrcore)"

VERSION: tuple = (2, 0, 0)  # major, minor, micro
VERSION_STRING: str = ".".join([str(element) for element in VERSION])

PLUGIN_NAME: str = "HashDB"
PLUGIN_NETNODE_ID: str = "$hashdb"     # unique netnode ID for database specific settings
PLUGIN_ACTIONS_PREFIX: str = "hashdb"  # prefixed to all actions (popup menu)
