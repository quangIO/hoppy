import subprocess

from utils import get_user_input


def danger():
    data = get_user_input()
    subprocess.call(data, shell=True)
