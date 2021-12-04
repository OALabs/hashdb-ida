# HashDB
from .action import Action, load_custom_icon
from ..ui.icons import HUNT_HASH_ICON_COMPRESSED
from ...settings.config import PLUGIN_HOTKEYS
from ...utilities.logging import info


class HuntHashAlgorithm(Action):
    def __init__(self):
        self.icon = load_custom_icon(HUNT_HASH_ICON_COMPRESSED)
        super().__init__(name="hunt_hash_algo",
                         label="Hunt Algorithm",
                         callback=self.action_callback,
                         shortcut=PLUGIN_HOTKEYS["hunt_hash_algo"],
                         tooltip="Try to find the hashing algorithm used for this hash",
                         icon=self.icon)

    # noinspection PyUnusedLocal
    @staticmethod
    def action_callback(context=None):
        info("HuntHashAlgorithm.action_callback")
