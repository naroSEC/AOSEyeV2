from threading import Event


class Cancelled(Exception):
    pass


class Cancellation:
    def __init__(self):
        self.event = Event()

    def cancel(self):
        self.event.set()

    def check(self):
        if self.event.is_set():
            raise Cancelled("Analysis cancelled")
