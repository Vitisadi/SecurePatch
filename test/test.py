import hashlib
import os
import random
import subprocess

user_input = input("Name: ")

password = "super-secret-password"

os.system("ls " + user_input)

subprocess.run("cat " + user_input, shell=True)

token = random.random()

hashlib.md5(b"example")
hashlib.sha1(b"example")
