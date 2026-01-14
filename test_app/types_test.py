class BaseController:
    def handle(self):
        pass


class AuthController(BaseController):
    def handle(self):
        print("Auth handle")


class GuestController(BaseController):
    def handle(self):
        print("Guest handle")


def run(c: BaseController):
    c.handle()


def main():
    a = AuthController()
    g = GuestController()
    run(a)
    run(g)
