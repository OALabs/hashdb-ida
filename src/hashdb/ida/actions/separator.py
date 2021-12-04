# HashDB
from .action import Action


class Separator(Action):
    def __init__(self):
        super().__init__(name="-", label="", callback=lambda _: None, name_prefix=False)
