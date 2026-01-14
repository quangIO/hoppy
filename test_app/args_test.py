import subprocess


def target_func():
    # Should match: first arg is literal "ls"
    subprocess.call("ls", shell=True)

    # Should NOT match: first arg is variable
    cmd = "echo hello"
    subprocess.call(cmd, shell=True)

    # Should NOT match: first arg is different literal
    subprocess.call("pwd", shell=True)


def another_func():
    # Should NOT match: wrong function
    print("ls")
