class ProtocolHandler:
    def __init__(self, encapsulating_layers={}, verbose=True, log=False):
        self.encapsulating_layers = encapsulating_layers
        self.verbose = verbose
        self.log = log
        self.cache = []

    def handle_packet(self, packet, idt=""):
        raise NotImplementedError("This method should be overridden by subclasses.")