import os

API_KEY = "sk-abcdef1234567890"  # hardcoded secret


def handle(user):
    os.system("ping " + user)  # command injection
