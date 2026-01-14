def check_auth():
    print("Checking auth...")


def safe_action():
    check_auth()
    sensitive_sink()


def unsafe_action():
    # Missing check_auth()
    sensitive_sink()


def sensitive_sink():
    print("Performing sensitive action")
