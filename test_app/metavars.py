def bug1():
    # Identical arguments
    match_this(1, 1)  # noqa: F821


def bug2():
    # Different arguments
    skip_this(1, 2)  # noqa: F821


def bug3():
    # Identical variables
    x = 10
    match_this(x, x)  # noqa: F821


def bug4():
    # Different variables
    x = 10
    y = 20
    skip_this(x, y)  # noqa: F821


def match_this(*args):
    pass


def skip_this(*args):
    pass
