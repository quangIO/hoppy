def get_input():
    return "dangerous_value"


def process(data):
    # Middleman
    return data


def sink(val):
    print(f"Executing: {val}")


def simple_vulnerable():
    a = get_input()
    sink(a)


def vulnerable():
    x = get_input()  # noqa: F841
    y = process(x)
    sink(y)


def safe_mismatch():
    x = get_input()  # noqa: F841

    y = process("other")

    sink(y)  # y is not from get_input()


def unification_match():
    z = get_input()

    process(z)

    sink(z)  # process(z) -> sink(z) same z


def complex_unification(user_data):
    # Requirement: $X must go to log($X) AND (system($X) OR exec($X))
    val = process(user_data)
    val = log(val)
    system(val)  # Match


def complex_unification_mismatch(user_data):
    other = "safe"
    val = process(user_data)
    val = log(val)
    system(other)  # Mismatch


def log(v):
    return v


def system(v):
    pass


def exec(v):
    pass


def intermediate_identifier_flow():
    src = get_input()
    a = src
    b = a
    sink_identifier(b)


def sink_identifier(val):
    pass
