# This library offers a wrapper class for the Requests library
# The wrapper transparently catches exceptions
# and returns appropriate HTTP status codes
# usage:
# import the library instead of requests
# from requests_wrapper import requests_wrapper as requests
# use it like the requests library
import requests


# Dummy return object for when exceptions are thrown
class Dummy():
    status_code = 503


# Requests wrapper class
class requests_wrapper():
    def get(baseurl, headers=None, cookies=None,
            params=None, allow_redirects=True):
        try:
            r = requests.get(baseurl, headers=headers, cookies=cookies,
                             params=params, allow_redirects=allow_redirects)
            return r
        except Exception:
            dummy = Dummy()
            return dummy

    def delete(baseurl, headers=None, cookies=None,
               params=None, allow_redirects=True):
        try:
            r = requests.delete(baseurl, headers=headers, cookies=cookies,
                                params=params, allow_redirects=allow_redirects)
            return r
        except Exception:
            dummy = Dummy()
            return dummy

    def post(baseurl, headers=None, cookies=None, params=None,
             data=None, files=None, allow_redirects=True):
        try:
            r = requests.post(baseurl, headers=headers, cookies=cookies,
                              params=params, data=data, files=files,
                              allow_redirects=allow_redirects)
            return r
        except Exception:
            dummy = Dummy()
            return dummy

    def put(baseurl, headers=None, cookies=None, params=None,
            data=None, files=None, allow_redirects=True):
        try:
            r = requests.put(baseurl, headers=headers, cookies=cookies,
                             params=params, data=data, files=files,
                             allow_redirects=allow_redirects)
            return r
        except Exception:
            dummy = Dummy()
            return dummy
