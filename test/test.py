import hashlib
import os
import random
import subprocess

user_input = input("Name: ")

password = os.environ.get("PASSWORD")

os.system("ls " + user_input)

subprocess.run(["cat", user_input])

token = random.random()

hashlib.md5(b"example")
hashlib.sha1(b"example")
