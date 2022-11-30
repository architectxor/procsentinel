#!/bin/python3
from ProcessesContext import *
import os


DEFAULT_STORAGE = "/tmp/procsent/"
UPDATE_INTERVAL = 300 # seconds == 5 minutes


def check_su_priv():
    if os.geteuid() != 0:
        exit("Run the scirpt with 'superuser' privileges!")


def main():
    check_su_priv()
    pc = ProcessesContext(DEFAULT_STORAGE)
    while True:
        time.sleep(UPDATE_INTERVAL)
        pc.update()


if __name__ == "__main__":
	main()
