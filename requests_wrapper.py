# This library offers a wrapper class for the Requests library
# The wrapper transparently catches exceptions
# and returns appropriate HTTP status codes
# usage:
# import the library instead of requests
# from requests_wrapper import requests_wrapper as requests
# use it like the requests library
import requests
import urllib3

# Disable invalid SSL warnings when explicitly asking to not check
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# To avoid hanging forever on requests
timeout_seconds=5

# Dummy return object for when exceptions are thrown
class Dummy():
    status_code = 503
    url = ""


# Requests wrapper class
class requests_wrapper():
    def get(baseurl,
            headers=None,
            cookies=None,
            params=None,
            allow_redirects=True,
            verify=True,
            timeout=timeout_seconds
           ):
        try:
            r = requests.get(baseurl,
                             headers=headers,
                             cookies=cookies,
                             params=params,
                             allow_redirects=allow_redirects,
                             verify=verify,
                             timeout=timeout_seconds
                            )
            return r
        except requests.exceptions.SSLError:
            dummy = Dummy()
            dummy.status_code = 526
            return dummy
        except requests.exceptions.ConnectionError:
            dummy = Dummy()
            return dummy
        except requests.exceptions.Timeout:
            dummy = Dummy()
            dummy.status_code = 408
            return dummy
        except OSError as ex:
            dummy = Dummy()
            dummy.status_code = 495
            return dummy
        except Exception:
            dummy = Dummy()
            return dummy

    def delete(baseurl,
               headers=None,
               cookies=None,
               params=None,
               allow_redirects=True,
               verify=True,
               timeout=timeout_seconds
              ):
        try:
            r = requests.delete(baseurl,
                                headers=headers,
                                cookies=cookies,
                                params=params,
                                allow_redirects=allow_redirects,
                                verify=verify,
                                timeout=timeout_seconds
                                )
            return r
        except requests.exceptions.SSLError:
            dummy = Dummy()
            dummy.status_code = 526
            return dummy
        except requests.exceptions.ConnectionError:
            dummy = Dummy()
            return dummy
        except OSError:
            dummy = Dummy()
            dummy.status_code = 495
            return dummy
        except Exception:
            dummy = Dummy()
            return dummy

    def post(baseurl,
             headers=None,
             cookies=None,
             params=None,
             data=None,
             files=None,
             allow_redirects=True,
             verify=True,
             timeout=timeout_seconds
            ):
        try:
            r = requests.post(baseurl,
                              headers=headers,
                              cookies=cookies,
                              params=params,
                              data=data,
                              files=files,
                              allow_redirects=allow_redirects,
                              verify=verify,
                              timeout=timeout_seconds
                             )
            return r
        except requests.exceptions.SSLError:
            dummy = Dummy()
            dummy.status_code = 526
            return dummy
        except requests.exceptions.ConnectionError:
            dummy = Dummy()
            return dummy
        except OSError:
            dummy = Dummy()
            dummy.status_code = 495
            return dummy
        except Exception:
            dummy = Dummy()
            return dummy

    def put(baseurl,
            headers=None,
            cookies=None,
            params=None,
            data=None,
            files=None,
            allow_redirects=True,
            verify=True,
            timeout=timeout_seconds
           ):
        try:
            r = requests.put(baseurl,
                             headers=headers,
                             cookies=cookies,
                             params=params,
                             data=data,
                             files=files,
                             allow_redirects=allow_redirects,
                             verify=verify,
                             timeout=timeout_seconds
                            )
            return r
        except requests.exceptions.SSLError:
            dummy = Dummy()
            dummy.status_code = 526
            return dummy
        except requests.exceptions.ConnectionError:
            dummy = Dummy()
            return dummy
        except OSError:
            dummy = Dummy()
            dummy.status_code = 495
            return dummy
        except Exception:
            dummy = Dummy()
            return dummy

    def patch(baseurl,
              headers=None,
              cookies=None,
              params=None,
              data=None,
              files=None,
              allow_redirects=True,
              verify=True,
              timeout=timeout_seconds
             ):
        try:
            r = requests.patch(baseurl,
                               headers=headers,
                               cookies=cookies,
                               params=params,
                               data=data,
                               files=files,
                               allow_redirects=allow_redirects,
                               verify=verify,
                               timeout=timeout_seconds
                              )
            return r
        except requests.exceptions.SSLError:
            dummy = Dummy()
            dummy.status_code = 526
            return dummy
        except requests.exceptions.ConnectionError:
            dummy = Dummy()
            return dummy
        except OSError:
            dummy = Dummy()
            dummy.status_code = 495
            return dummy
        except Exception:
            dummy = Dummy()
            return dummy
