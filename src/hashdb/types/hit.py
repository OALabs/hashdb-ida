class Hit:
    """
    Interface for a hash hits.
    """
    name: str       # algorithm name
    count: int      # number of hits
    hitrate: float  # hit rate

    def __init__(self, name: str, count: int, hitrate: float):
        self.name = name
        self.count = count
        self.hitrate = hitrate
