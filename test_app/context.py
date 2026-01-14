def safe_func():
    eval("1+1")


def unsafe_func():
    eval("os.system('rm -rf /')")


def untrusted_caller():
    # some logic
    pass
