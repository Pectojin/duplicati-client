import unittest
from mock import patch
from auth import login
import common
import requests


class TestLogin(unittest.TestCase):

    def mock_write_config(self):
        pass

    def mock_requests_get(*args, **kwargs):
        class MockResponse:
            def __init__(self, status_code, headers, url, cookies):
                self.status_code = status_code
                self.headers = headers
                self.url = url
                self.cookies = cookies

        if args[0] == 'http://duplicati_proxy:80':
            headers = {'Server': 'nginx/1.13.8',
                       'Date': 'Wed, 13 Jun 2018 18:28:32 GMT',
                       'Content-Type': 'text/html',
                       'Content-Length': '195',
                       'Connection': 'keep-alive',
                       'WWW-Authenticate':
                       'Basic realm="Restricted duplicati.test.net"'
                       }
            cookies = {"xsrf-token":
                       "sF02%2FyeH5oXieSAB%2FCRf4bsZuR1UHQGx5wmceEacWlg%3D"}
            return MockResponse(200, headers, args[0], cookies)
        elif args[0] == 'http://localhost:8200':
            headers = {'Cache-Control': 'max-age=86400',
                       'Last-modified': 'Mon, 02 Apr 2018 12:00:08 GMT',
                       'Date': 'Wed, 13 Jun 2018 20:45:29 GMT',
                       'Content-Length': '1189',
                       'Content-Type': 'text/html; charset=utf-8',
                       'Server': 'Tiny WebServer',
                       'Keep-Alive': 'timeout=20, max=400',
                       'Connection': 'Keep-Alive'}
            cookies = {"xsrf-token":
                       "sF02%2FyeH5oXieSAB%2FCRf4bsZuR1UHQGx5wmceEacWlg%3D"}
            return MockResponse(200, headers, args[0], cookies)

    def mock_requests_get_redirect(*args, **kwargs):
        """simulates the redirect for login"""
        class MockResponse:
            def __init__(self, status_code, headers, url, cookies):
                self.status_code = status_code
                self.headers = headers
                self.url = url + "/login.html"
                self.cookies = cookies

        if args[0] == 'http://duplicati_proxy:80':
            headers = {'Server': 'nginx/1.13.8',
                       'Date': 'Wed, 13 Jun 2018 18:28:32 GMT',
                       'Content-Type': 'text/html',
                       'Content-Length': '195',
                       'Connection': 'keep-alive',
                       'WWW-Authenticate':
                       'Basic realm="Restricted duplicati.test.net"'
                       }
            return MockResponse(200, headers, args[0])
        elif args[0] == 'http://localhost:8200':
            headers = {'Cache-Control': 'max-age=86400',
                       'Last-modified': 'Mon, 02 Apr 2018 12:00:08 GMT',
                       'Date': 'Wed, 13 Jun 2018 20:45:29 GMT',
                       'Content-Length': '1189',
                       'Content-Type': 'text/html; charset=utf-8',
                       'Server': 'Tiny WebServer',
                       'Keep-Alive': 'timeout=20, max=400',
                       'Connection': 'Keep-Alive'}
            cookies = {"xsrf-token":
                       "sF02%2FyeH5oXieSAB%2FCRf4bsZuR1UHQGx5wmceEacWlg%3D"}
            return MockResponse(200, headers, args[0], cookies)

    def mock_requests_post(*args, **kwargs):
        class MockResponse:
            def __init__(self, status_code, headers, url, cookies, json_raw):
                self.status_code = status_code
                self.headers = headers
                self.url = url
                self.cookies = cookies
                self.json_raw = json_raw

            def json(self):
                return self.json_raw

        if args[0] == 'http://duplicati_proxy:8200':
            headers = {'Server': 'nginx/1.13.8',
                       'Date': 'Wed, 13 Jun 2018 18:28:32 GMT',
                       'Content-Type': 'text/html',
                       'Content-Length': '195',
                       'Connection': 'keep-alive',
                       'WWW-Authenticate':
                       'Basic realm="Restricted duplicati.test.net"'
                       }
            return MockResponse(200, headers, args[0])
        elif args[0] == 'http://localhost:8200/login.cgi':
            headers = {'Cache-Control': 'max-age=86400',
                       'Last-modified': 'Mon, 02 Apr 2018 12:00:08 GMT',
                       'Date': 'Wed, 13 Jun 2018 20:45:29 GMT',
                       'Content-Length': '1189',
                       'Content-Type': 'text/html; charset=utf-8',
                       'Server': 'Tiny WebServer',
                       'Keep-Alive': 'timeout=20, max=400',
                       'Connection': 'Keep-Alive'}
            cookies = {"xsrf-token":
                       "sF02%2FyeH5oXieSAB%2FCRf4bsZuR1UHQGx5wmceEacWlg%3D",
                       "session-auth":
                       "63bgjHEmpOrQuZS2ubupqBiB5mJeU9A3yQWbSQql1n0"}
            json = {'Status': 'OK',
                    'Nonce': 'rK44ZOGiWJKk+aDluN/b60MlwXGbQcRc9SnuxSHv784=',
                    'Salt': 'H9euyRJMYftnoDGro2TC4tEMsQ/BCpZ5dVSBRN1cDC4='}
            return MockResponse(200, headers, args[0], cookies, json)

    @patch('requests.get', side_effect=mock_requests_get)
    @patch('common.write_config', side_effect=mock_write_config)
    def test_integrated_auth_logged_in(self, mock_requests_get,
                                       mock_write_config):
        """This test case validates that login works when no
           login redirect happens"""
        data = {
            "last_login": None,
            "parameters_file": None,
            "server": {
                "port": "8200",
                "protocol": "http",
                "url": "localhost",
                "verify": True
                },
            'token': None,
            'token_expires': None,
            'verbose': False,
            'authorization': ''
            }
        try:
            auth = login(data, input_url=None, password=None, verify=True,
                         interactive=True, basic_user=None, basic_pass=None)
            self.assertEqual(auth, True)
        finally:
            pass

    @patch('requests.get', side_effect=mock_requests_get_redirect)
    @patch('common.write_config', side_effect=mock_write_config)
    @patch('requests.post', side_effect=mock_requests_post)
    def test_integrated_auth_not_logged_in(self, mock_requests_get,
                                           mock_write_config,
                                           mock_requests_post
                                           ):
        """This test case validates that login works when
           login redirect happens"""
        data = {
            "last_login": None,
            "parameters_file": None,
            "server": {
                "port": "8200",
                "protocol": "http",
                "url": "localhost",
                "verify": True
                },
            'token': None,
            'token_expires': None,
            'verbose': False,
            'authorization': ''
            }

        try:
            auth = login(data, input_url=None, password='1234', verify=True,
                         interactive=False, basic_user=None, basic_pass=None)
            self.assertEqual(auth, True)
        finally:
            pass

    @patch('requests.get', side_effect=mock_requests_get)
    @patch('common.write_config', side_effect=mock_write_config)
    @patch('requests.post', side_effect=mock_requests_post)
    def test_basic_auth_not_logged_in(self, mock_requests_get,
                                      mock_write_config,
                                      mock_requests_post
                                      ):
        """This test case validates that login works when
           login redirect happens"""
        data = {
            "last_login": None,
            "parameters_file": None,
            "server": {
                "port": "80",
                "protocol": "http",
                "url": "duplicati_proxy",
                "verify": True
                },
            'token': None,
            'token_expires': None,
            'verbose': False,
            'authorization': ''
            }

        try:
            auth = login(data, input_url=None, password='1234', verify=True,
                         interactive=False, basic_user='duplicati',
                         basic_pass='1234')
            self.assertEqual(auth, True)
        finally:
            pass


class TestResponse(unittest.TestCase):
    def setUp(self):
        self.data = {
            "last_login": None,
            "parameters_file": None,
            "server": {
                "port": "8200",
                "protocol": "http",
                "url": "localhost",
                "verify": True
                },
            'token': None,
            'token_expires': None,
            'verbose': False,
            'authorization': ''
            }

    def test_response_400(self):
        try:
            with self.assertRaises(SystemExit) as cm:
                common.check_response(self.data, 400)
            self.assertEqual(cm.exception.code, 2)
        finally:
            pass

    def test_response_526(self):
        try:
            with self.assertRaises(SystemExit) as cm:
                common.check_response(self.data, 526)
            self.assertEqual(cm.exception.code, 2)
        finally:
            pass

    def test_response_495(self):
        try:
            with self.assertRaises(SystemExit) as cm:
                common.check_response(self.data, 495)
            self.assertEqual(cm.exception.code, 2)
        finally:
            pass

    def test_response_503(self):
        try:
            with self.assertRaises(SystemExit) as cm:
                common.check_response(self.data, 503)
            self.assertEqual(cm.exception.code, 2)
        finally:
            pass


class TestResponse200(unittest.TestCase):
    # mocking the write_config function
    def mock_write_config(self):
        pass

    @patch('common.write_config', side_effect=mock_write_config)
    def test_response_200(self, write_config):
        data = {
            "last_login": None,
            "parameters_file": None,
            "server": {
                "port": "8200",
                "protocol": "http",
                "url": "localhost",
                "verify": True
                },
            'token': None,
            'token_expires': None,
            'verbose': False,
            'authorization': ''
            }
        common.check_response(data, 200)
