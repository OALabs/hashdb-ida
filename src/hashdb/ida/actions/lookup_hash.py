# HashDB
from .action import Action, load_custom_icon
from ..ui.icons import LOOKUP_HASH_ICON_COMPRESSED
from ...settings.config import PLUGIN_HOTKEYS
from ...utilities.logging import info


class LookupHash(Action):
    def __init__(self):
        self.icon = load_custom_icon(LOOKUP_HASH_ICON_COMPRESSED)
        super().__init__(name="lookup_hash",
                         label="Lookup Hash",
                         callback=self.action_callback,
                         shortcut=PLUGIN_HOTKEYS["lookup_hash"],
                         tooltip="Try to lookup a hash",
                         icon=self.icon)

    # noinspection PyUnusedLocal
    @staticmethod
    def action_callback(context=None):
        info("LookupHash.action_callback")
