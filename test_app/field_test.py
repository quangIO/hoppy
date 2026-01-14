class User:
    def __init__(self, name, id):
        self.name = name
        self.id = id


def get_input():
    return "tainted"


def sink(val):
    print(val)


def test_field_direct():
    x = get_input()

    class Obj:
        prop: str

    o = Obj()
    o.prop = x
    sink(o.prop)
