from os.path import getmtime
from email.utils import formatdate
import requests

print("Show that the file has not been modified \"since one hour in the future\"")
filename = input("Type the name of the file (under /files/):")

ts = getmtime(f"./jail/content/files/{filename}")

# I make a conditional GET request and show that it returns the status code '304'
x = requests.get(f"http://localhost:3456/files/{filename}", headers={
    "If-Modified-Since": formatdate(ts+3600)
})

print(f"{x.status_code = }\n{x.headers = }\n{x.text = }")
