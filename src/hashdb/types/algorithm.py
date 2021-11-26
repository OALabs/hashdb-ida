class Algorithm:
    """
    Interface for a hash algorithm.
    """
    name: str
    size: int

    def __init__(self, name: str, size: int):
        self.name = name
        self.size = size
