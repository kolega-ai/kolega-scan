import os
import subprocess

api_key = os.environ["API_KEY"]  # safe: from env


def handle(args):
    subprocess.run(["ls", "-l"], check=True)  # safe: no shell
