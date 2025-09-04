# This is supposed to be tested against the fileServer service, exposing the "/www/*" folder pattern.
# PUTs are directed onto ./content/www/put.html
# DELETEs are directed onto ./content/www/delete.html

import unittest
import requests
import string
from time import time
from email.utils import formatdate, parsedate # RFC 2822 date format
from os.path import getmtime
import calendar

class TestCommonFeatures(unittest.TestCase):
            
    def test_head(self):
        r = requests.head("http://localhost:3456/www/index.html")
        self.assertEqual(r.text, "")

    def test_get(self):
        r = requests.get("http://localhost:3456/www/index.html")
        with open("./content/www/index.html") as file:
            fileData = file.read()
        self.assertEqual(r.text, fileData)

    def test_post(self):
        r = requests.post("http://localhost:3456/www/test.html", data=string.printable)
        with open("./content/www/test.html") as file:
            fileData = file.read()
        self.assertEqual(r.status_code, 200)

    def test_empty_post(self):
        r = requests.post("http://localhost:3456/www/test.html", data="")
        with open("./content/www/test.html") as file:
            fileData = file.read()
        self.assertEqual(r.status_code, 200)

    def test_put(self):
        with open("./content/www/put.html", "w"):
            pass

        ts = time()
        r = requests.put("http://localhost:3456/www/put.html", data=f"{ts}")
        self.assertEqual(r.status_code, 200)
        s = requests.get("http://localhost:3456/www/put.html")
        self.assertEqual(s.text, f"{ts}")

    def test_empty_put(self):
        with open("./content/www/put.html", "w"):
            pass

        ts = time()
        r = requests.put("http://localhost:3456/www/put.html", data="")
        self.assertEqual(r.status_code, 200)
        s = requests.get("http://localhost:3456/www/put.html")
        self.assertEqual(s.text, f"")

    def test_delete(self):
        with open("./content/www/delete.html", "w"):
            pass
        r = requests.delete("http://localhost:3456/www/delete.html")
        with self.assertRaises(FileNotFoundError):
            with open("./content/www/delete.html"):
                pass

    # Checking basic GET and HEAD response caching behaviour with
    # If-Modified-Since and Expires headers
    def test_caching(self):
        s = requests.Session()
        
        ts = getmtime("./content/www/index.html")

        # first request
        r = s.get("http://localhost:3456/www/index.html")
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.headers.get("Expires"),None)
        self.assertEqual(checkTimes(r), True)

        # head should be cached
        r = s.head("http://localhost:3456/www/index.html")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(checkTimes(r), True)
        
        # modified since 1 hour in the past? GET & HEAD
        r = s.get("http://localhost:3456/www/index.html", headers={
            "If-Modified-Since": formatdate(ts-3600)
        })
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.headers.get("Expires"),None)
        
        r = s.head("http://localhost:3456/www/index.html", headers={
            "If-Modified-Since": formatdate(ts-3600)
        })
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.headers.get("Expires"),None)

        # modified since 1 hour in the future? GET & HEAD
        r = s.get("http://localhost:3456/www/index.html", headers={
            "If-Modified-Since": formatdate(ts+3600)
        })
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.headers.get("Expires"),None)

        r = s.head("http://localhost:3456/www/index.html", headers={
            "If-Modified-Since": formatdate(ts+3600)
        })
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.headers.get("Expires"),None)

    # Caching should only be supported for the GET and HEAD methods,
    # here I'm checking if it enforced
    def test_wrong_method_caching(self):
        s = requests.Session()
        
        with open("./content/www/test.html", "w"):
            pass
        
        ts_test = getmtime("./content/www/test.html")
        ts = time() # some random enough data

        # first request
        r = s.get("http://localhost:3456/www/test.html")
        self.assertEqual(r.status_code, 200)        
        
        # POST
        r = s.post("http://localhost:3456/www/test.html", headers={
            "If-Modified-Since": formatdate(ts+3600)
        }, data=f"{ts}")
        self.assertEqual(r.status_code, 200)

        # PUT
        r = s.put("http://localhost:3456/www/test.html", headers={
            "If-Modified-Since": formatdate(ts+3600)
        }, data=f"{ts}")
        self.assertEqual(r.status_code, 200)

        # DELETE
        r = s.delete("http://localhost:3456/www/test.html", headers={
            "If-Modified-Since": formatdate(ts+3600)
        }, data=f"{ts}")
        self.assertEqual(r.status_code, 200)

class TestSecurityFeatures(unittest.TestCase):

    def test_path_traversal(self):
        for payload in [
            "http://localhost:3456/../../../../../../../../../../../../../../etc/passwd",
            "http://localhost:3456/../notexistingfolder",
            "http://localhost:3456/./",
        ]:    
            r = requests.get(payload)
            self.assertNotIn(r.status_code, [200, 304, 500])
    
        for payload in [
            "http://localhost:3456/",
        ]:    
            r = requests.get(payload)
            self.assertEqual(r.status_code, 404)

# Takes a requests module response and returns whether the Last-Modified and Expires headers are at a distance of one hour
def checkTimes(r):
    # Expires and Last-Modified headers
    ts_exp = calendar.timegm(parsedate(r.headers.get('Expires')))
    ts_lastmod = calendar.timegm(parsedate(r.headers.get('Last-Modified')))
    print(f"{ts_exp=} {ts_lastmod=}")
    return ts_exp == ts_lastmod + 3600

if __name__ == '__main__':
    unittest.main(verbosity=2)