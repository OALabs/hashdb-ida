# HashDB
from .action import Action, load_custom_icon
from ..ui.icons import SCAN_HASHES_ICON_COMPRESSED
from ...settings.config import PLUGIN_HOTKEYS
from ...utilities.logging import info


class ScanHashes(Action):
    def __init__(self):
        self.icon = load_custom_icon(SCAN_HASHES_ICON_COMPRESSED)
        super().__init__(name="scan_hashes",
                         label="Scan Hashes",
                         callback=self.action_callback,
                         shortcut=PLUGIN_HOTKEYS["scan_hashes"],
                         tooltip="Try to lookup multiple hashes at once",
                         icon=self.icon)

    # noinspection PyUnusedLocal
    @staticmethod
    def action_callback(context=None):
        info("ScanHashes.action_callback")
