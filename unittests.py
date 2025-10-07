# This is supposed to be tested against the fileServer service, exposing the "/files/*" folder pattern.
# PUTs are directed onto ./jail/content/files/put.html
# DELETEs are directed onto ./jail/content/files/delete.html

import unittest
import requests
import string
from time import time
from email.utils import formatdate, parsedate # RFC 2822 date format
from os.path import getmtime
from os import unlink, system
import calendar

URL = "http://localhost:3456"

class TestFileHandlerFeatures(unittest.TestCase):
            
    def test_head(self):
        with open("./jail/content/files/get.html", "w"):
            pass

        r = requests.head(URL+"/files/get.html")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, "")

        unlink("./jail/content/files/get.html")

    def test_get(self):
        with open("./jail/content/files/get.html", "w"):
            pass

        r = requests.get(URL+"/files/get.html")
        self.assertEqual(r.status_code, 200)
        with open("./jail/content/files/get.html", 'rb') as file:
            fileData = file.read()
        self.assertEqual(r.content, fileData)

        unlink("./jail/content/files/get.html")

    # we must be able to create a file with arbitrary binary data
    def test_post_bin(self):
        try:
            unlink("./jail/content/files/post.html")
        except:
            pass
        everyChar = bytes([x for x in range(0, 256)])
        r = requests.post(URL+"/files/post.html", data=everyChar)
        self.assertEqual(r.status_code, 200)
        with open("./jail/content/files/post.html", 'rb') as file:
            fileData = file.read()
        self.assertEqual(everyChar, fileData)
        unlink("./jail/content/files/post.html")

    # we must be able to create an empty file
    def test_empty_post(self):
        try:
            unlink("./jail/content/files/epost.html")
        except:
            pass
        r = requests.post(URL+"/files/epost.html", data="")
        self.assertEqual(r.status_code, 200)
        with open("./jail/content/files/epost.html", 'rb') as file:
            fileData = file.read()
        self.assertEqual(bytes("", 'utf-8'), fileData)
        unlink("./jail/content/files/epost.html")

    # we must not be able to create a file with PUT, requires GET and PUT to work
    def test_put_create(self):
        try:
            unlink("./jail/content/files/cput.html")
        except:
            pass

        ts = time()
        r = requests.put(URL+"/files/cput.html", data=f"{ts}")
        self.assertEqual(r.status_code, 404)
        s = requests.get(URL+"/files/cput.html")
        self.assertEqual(r.status_code, 404)

    # we must be able to update an existing file
    def test_put(self):
        with open("./jail/content/files/put.html", "w"):
            pass

        ts = time()
        r = requests.put(URL+"/files/put.html", data=f"{ts}")
        self.assertEqual(r.status_code, 200)
        s = requests.get(URL+"/files/put.html")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(s.text, f"{ts}")

        unlink("./jail/content/files/put.html")

    # we must be able to update an existing file with empty data
    def test_empty_put(self):
        with open("./jail/content/files/put.html", "w"):
            pass

        ts = time()
        r = requests.put(URL+"/files/put.html", data="")
        self.assertEqual(r.status_code, 200)
        s = requests.get(URL+"/files/put.html")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(s.text, f"")

        unlink("./jail/content/files/put.html")

    def test_delete(self):
        with open("./jail/content/files/delete.html", "w"):
            pass
        r = requests.delete(URL+"/files/delete.html")
        with self.assertRaises(FileNotFoundError):
            with open("./jail/content/files/delete.html"):
                pass

    def test_too_many_headers(self):
        headers = dict()
        for i in range(100):
            headers.setdefault(f"LotsOf{i}", f"Headers{i}")
        r = requests.get(URL+"/", headers=headers)
        self.assertIn(r.status_code, [400, 413])

class TestCaching(unittest.TestCase):

    # Checking basic GET and HEAD response caching behaviour with
    # If-Modified-Since and Expires headers
    def test_caching(self):
        with open("./jail/content/files/get.html", "w"):
            pass
        
        s = requests.Session()
        
        ts = getmtime("./jail/content/files/get.html")

        # first request
        r = s.get(URL+"/files/get.html")
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.headers.get("Expires"),None)
        self.assertEqual(checkTimes(r), True)

        # head should be cached
        r = s.head(URL+"/files/get.html")
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.headers.get("Expires"),None)
        self.assertEqual(checkTimes(r), True)
        
        # modified since 1 hour in the past? GET & HEAD
        r = s.get(URL+"/files/get.html", headers={
            "If-Modified-Since": formatdate(ts-3600)
        })
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.headers.get("Expires"),None)
        
        r = s.head(URL+"/files/get.html", headers={
            "If-Modified-Since": formatdate(ts-3600)
        })
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.headers.get("Expires"),None)

        # modified since 1 hour in the future? GET & HEAD
        r = s.get(URL+"/files/get.html", headers={
            "If-Modified-Since": formatdate(ts+3600)
        })
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.headers.get("Expires"),None)

        r = s.head(URL+"/files/get.html", headers={
            "If-Modified-Since": formatdate(ts+3600)
        })
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.headers.get("Expires"),None)

        unlink("./jail/content/files/get.html")

    # Caching should only be supported for the GET and HEAD methods,
    # here I'm checking if it enforced
    def test_wrong_method_caching(self):
        s = requests.Session()
        
        with open("./jail/content/files/test.html", "w"):
            pass
        
        ts_test = getmtime("./jail/content/files/test.html")
        ts = time() # some random enough data

        # first request
        r = s.get(URL+"/files/test.html")
        self.assertEqual(r.status_code, 200)        
        
        # POST
        r = s.post(URL+"/files/test.html", headers={
            "If-Modified-Since": formatdate(ts+3600)
        }, data=f"{ts}")
        self.assertEqual(r.status_code, 200)

        # PUT
        r = s.put(URL+"/files/test.html", headers={
            "If-Modified-Since": formatdate(ts+3600)
        }, data=f"{ts}")
        self.assertEqual(r.status_code, 200)

        # DELETE
        r = s.delete(URL+"/files/test.html", headers={
            "If-Modified-Since": formatdate(ts+3600)
        }, data=f"{ts}")
        self.assertEqual(r.status_code, 200)

# We must ensure that the server responds with the correct request handler.
# Other test cases would be the same as the TestFileHandlerFeatures class.
class TestWebHandlerFeatures(unittest.TestCase):
            
    # open a file that only the web server can serve 
    def test_get(self):
        r = requests.get(URL+"/www/webserveronly.html")
        self.assertEqual(r.status_code, 200)
        with open("./jail/content/www/webserveronly.html") as file:
            fileData = file.read()
        self.assertEqual(r.text, fileData)

class TestCookieFeatures(unittest.TestCase):

    # the login endpoint should set a cookie "username=user; SameSite=Strict;"
    def test_cookie_login(self):
        s = requests.Session()
        r = s.get(URL+"/www/login")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(s.cookies.get("username"), "user")

    # the logout endpoint should set a cookie "username=; SameSite=Strict;"
    def test_cookie_logout(self):
        s = requests.Session()
        r = s.get(URL+"/www/logout")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(s.cookies.get("username"), None)

# class TestContentTypeNegotiation(unittest.TestCase):

#     # how do I check for content type negotiation?
#     # I create different files with different extension and requests them,
#     # the server must respond with the correct content.
#     # If more than one item satisfies the request, then the first one is returned.
#     # If none of the required media types satisfy the request, 404 is returned.
#     def test_content_type(self):
#         with open("./jail/content/files/ctn.html", "w"):
#             pass
#         with open("./jail/content/files/ctn.xml", "w"):
#             pass
#         with open("./jail/content/files/ctn.jpeg", "w"):
#             pass

#         requests.get(URL+"/www/files/ctn", headers={"Accept": "text/html, text/plain; q=0.5, text/x-dvi; q=0.8"})
#         requests.get(URL+"/www/files/ctn", headers={"Accept": "text/plain; q=0.5, text/x-dvi; q=0.8, text/html"})
#         requests.get(URL+"/www/files/ctn", headers={"Accept": "text/plain; q=0.5, text/x-jpeg; q=0.8, text/html"})

#         unlink("./jail/content/files/ctn.html")
#         unlink("./jail/content/files/ctn.xml")
#         unlink("./jail/content/files/ctn.jpeg")

class TestSecurityFeatures(unittest.TestCase):

    def test_path_traversal(self):
        r = requests.get(URL+"/../../../../../../../../../../../../../../etc/passwd")
        self.assertNotIn(r.status_code, [200, 304, 500])
        r = requests.get(URL+"/../notexistingfolder")
        self.assertNotIn(r.status_code, [200, 304, 500])
        r = requests.get(URL+"/./")
        self.assertNotIn(r.status_code, [200, 304, 500])
        r = requests.get(URL+"/")
        self.assertEqual(r.status_code, 404)
    
    def test_persistent_connection(self):
        s = requests.Session()
        for i in range(1000):
            r = s.get(URL+"/www/index.html")
            self.assertEqual(r.status_code, 200)
        system("rm ./logs/*.log")

# Takes a requests module response and returns whether the Last-Modified and Expires headers are at a distance of one hour
def checkTimes(r):
    # Expires and Last-Modified headers
    ts_exp = calendar.timegm(parsedate(r.headers.get('Expires')))
    ts_lastmod = calendar.timegm(parsedate(r.headers.get('Last-Modified')))
    print(f"{ts_exp=} {ts_lastmod=}")
    return ts_exp == ts_lastmod + 3600

if __name__ == '__main__':
    unittest.main(verbosity=2)
