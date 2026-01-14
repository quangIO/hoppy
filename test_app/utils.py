import flask  # type: ignore[unresolved-import]


def get_user_input():
    return flask.request.args.get("cmd")
