class Compose:
    def __init__(self, wss_objects):
        self.wss_objects = wss_objects

    def apply(self, envelope, headers):
        for obj in self.wss_objects:
            envelope, headers = obj.apply(envelope, headers)
        return envelope, headers

    def verify(self, envelope):
        for obj in self.wss_objects:
            obj.verify(envelope)
