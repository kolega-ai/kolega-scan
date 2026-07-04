import subprocess


def list_dir():
    subprocess.run(["ls", "-l"], check=True)
