# Module for handling authentication against the Duplicati API
import base64
import sys
import datetime
import common
import getpass
import hashlib
import re
import compatibility

from requests_wrapper import requests_wrapper as requests
from os.path import expanduser


# Login by authenticating against the Duplicati API and extracting a token
def login(data, input_url=None, password=None, verify=True,
          interactive=True, basic_user=None):
    if input_url is None:
        input_url = ""

    # Split protocol, url, and port
    input_url = input_url.replace("/", "").replace("_", "")
    count = input_url.count(":")
    protocol = ""
    url = ""
    port = ""
    if count == 2:
        protocol, url, port = input_url.split(":")
    elif count == 1 and input_url.index(":") < 6:
        protocol, url = input_url.split(":")
    elif count == 1:
        url, port = input_url.split(":")
    elif count == 0:
        url = input_url
    else:
        common.log_output("Invalid URL", True)
        sys.exit(2)

    # Strip nondigits
    port = ''.join(re.findall(r'\d+', port))

    # Default to config file values for any missing parameters
    if protocol is None or protocol.lower() not in ["http", "https"]:
        protocol = data["server"]["protocol"]
    if url is None or url == "":
        url = data["server"]["url"]
    if port is None or port == "":
        port = data["server"]["port"]

    # Update config
    data["server"]["protocol"] = protocol
    data["server"]["url"] = url
    data["server"]["port"] = port

    # Make the login attempt
    baseurl = common.create_baseurl(data, "")
    common.log_output("Connecting to " + baseurl + "...", False)
    r = requests.get(baseurl, allow_redirects=True, verify=verify)
    common.check_response(data, r.status_code)

    # Detect if we were redirected to https
    if "https://" in r.url and protocol != "https":
        data["server"]["protocol"] = "https"
        common.log_output("Redirected from http to https", True)

    # Detect if we're prompted for basic authentication
    auth_method = r.headers.get('WWW-Authenticate', False)
    if (auth_method):
        common.log_output('Server requests basic auth...', False)
        # Create the basic auth secret
        secret = base64.b64encode((basic_user+":"+password).encode('ascii'))
        # Create the authorization string
        basic_auth = "Basic " + secret.decode('utf-8')
        headers = {"Authorization": basic_auth}
        r = requests.get(baseurl, verify=verify, headers=headers,
                         allow_redirects=True)
        common.check_response(data, r.status_code)
        if r.status_code == 200:
            common.log_output('Passed basic auth', False)
            # Update basic auth secret in config file
            data['basic_auth'] = basic_auth

    # Detect if we were prompted to login
    login_redirect = "/login.html" in r.url

    if r.status_code == 200 and not login_redirect:
        common.log_output("OK", False, r.status_code)
        token = compatibility.unquote(r.cookies["xsrf-token"])
    elif r.status_code == 200 and login_redirect:
        # Get password by prompting user if no password was given in-line
        if password is None and interactive:
            common.log_output("Authentication required", False, r.status_code)
            password = getpass.getpass('Password:')
        elif password is None and not interactive:
            common.log_output("A password is required required", True)
            sys.exit(2)

        common.log_output("Getting nonce and salt...", False)
        baseurl = common.create_baseurl(data, "/login.cgi")
        headers = common.create_headers(data)
        payload = {'get-nonce': 1}
        r = requests.post(baseurl, headers=headers, data=payload, verify=verify)
        if r.status_code != 200:
            common.log_output("Error getting salt from server", True, r.status_code)
            sys.exit(2)

        salt = r.json()["Salt"]
        data["nonce"] = compatibility.unquote(r.json()["Nonce"])
        token = compatibility.unquote(r.cookies["xsrf-token"])
        common.log_output("Hashing password...", False)
        salt_password = password.encode() + base64.b64decode(salt)
        saltedpwd = hashlib.sha256(salt_password).digest()
        nonce_password = base64.b64decode(data["nonce"]) + saltedpwd
        noncedpwd = hashlib.sha256(nonce_password).digest()

        common.log_output("Authenticating... ", False)
        payload = {
            "password": base64.b64encode(noncedpwd).decode('utf-8')
        }
        cookies = {
            "xsrf-token": token,
            "session-nonce": data.get("nonce", "")
        }
        r = requests.post(baseurl, headers=headers, data=payload,
                          cookies=cookies, verify=verify)
        common.check_response(data, r.status_code)
        if r.status_code == 200:
            common.log_output("Connected", False, r.status_code)
            data["session-auth"] = compatibility.unquote(r.cookies["session-auth"])
        else:
            message = "Error authenticating against the server"
            common.log_output(message, True, r.status_code)
            sys.exit(2)
    else:
        message = "Error connecting to server"
        common.log_output(message, True, r.status_code)
        sys.exit(2)

    # Update the config file with provided values
    data["token"] = token
    expiration = datetime.datetime.now() + datetime.timedelta(0, 600)
    data["token_expires"] = expiration
    data["last_login"] = datetime.datetime.now()
    common.write_config(data)
    common.log_output("Login successful", True)
    return True


# Logout by deleting the token from memory and disk
def logout(data):
    common.log_output("Logging out...", True)
    data['token'] = None
    data['basic_auth'] = None
    common.write_config(data)
    return data


# Determine if and how we validate SSL
def determine_ssl_validation(data, certfile=None, insecure=False):
    if certfile is not None:
        data["server"]["verify"] = expanduser(certfile)
    elif insecure:
        data["server"]["verify"] = False
    else:
        data["server"]["verify"] = True
    common.write_config(data)
    return data["server"]["verify"]
