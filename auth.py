# Module for handling authentication against the Duplicati API
import base64
import common
import compatibility
import datetime
import getpass
import hashlib
import json
import random
import re
import sys
import urllib

from os.path import expanduser
from requests_wrapper import requests_wrapper as requests

# Allowed alphabet for generating salts
ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"


# Login by authenticating against the Duplicati API and extracting a token
def login(data, input_url=None, password=None, verify=True,
          interactive=True, basic_user=None, basic_pass=None):
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
        common.log_output('Basic authentication required...', False)
        if basic_user is None and interactive:
            basic_user = input('Basic username: ')
        elif basic_user is None and not interactive:
            message = 'You must provide a basic auth username, --basic-user'
            common.log_output(message, True)
            sys.exit(2)

        if basic_pass is None and interactive:
            basic_pass = getpass.getpass('Basic password:')
        elif basic_pass is None and password is not None:
            basic_pass = password
        elif basic_pass and password:
            pass
        else:
            common.log_output("A password is required required", True)
            sys.exit(2)

        # Create the basic auth secret
        secret = base64.b64encode((basic_user+":"+basic_pass).encode('ascii'))
        # Create the authorization string
        basic_auth = "Basic " + secret.decode('utf-8')
        headers = {"Authorization": basic_auth}
        r = requests.get(baseurl, verify=verify, headers=headers,
                         allow_redirects=True)
        common.check_response(data, r.status_code)
        if r.status_code == 200:
            common.log_output('Passed basic auth', False)
            # Update basic auth secret in config file
            data['authorization'] = basic_auth

    # Detect if we were prompted to login
    login_redirect = "/login.html" in r.url

    if r.status_code == 200 and not login_redirect:
        common.log_output("OK", False, r.status_code)
        token = urllib.parse.unquote(r.cookies["xsrf-token"])
    elif r.status_code == 200 and login_redirect:
        password = prompt_password(password, interactive)

        common.log_output("Getting nonce and salt...", False)
        baseurl = common.create_baseurl(data, "/login.cgi")
        headers = common.create_headers(data)
        payload = {'get-nonce': 1}
        r = requests.post(baseurl, headers=headers, data=payload,
                          verify=verify)
        if r.status_code != 200:
            common.log_output("Error getting salt from server", True,
                              r.status_code)
            sys.exit(2)

        r.encoding='utf-8-sig'          
        salt = r.json()["Salt"]
        data["nonce"] = urllib.parse.unquote(r.json()["Nonce"])
        token = urllib.parse.unquote(r.cookies["xsrf-token"])
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
            data["session-auth"] = urllib.parse.unquote(
                                        r.cookies["session-auth"])
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
    return data


# Logout by deleting the token from memory and disk
def logout(data):
    common.log_output("Logging out...", True)
    data['token'] = None
    data['basic_auth'] = None
    common.write_config(data)
    return data


# Set server password
def set_password(data, password=None, disable_login=False, interactive=True):
    common.verify_token(data)

    if not disable_login:
        password = prompt_password(password, interactive)

    common.log_output("Setting server password...", False)
    baseurl = common.create_baseurl(data, "/api/v1/serversettings")
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)

    if disable_login:
        password = None
    if password is None:
        salt = None
        hashed_password = None
    else:
        # Generate a salt
        salt = ''.join(random.choice(ALPHABET) for i in range(44))
        # Hash the password and salt
        salt_password = password.encode() + base64.b64decode(salt)
        hashed_password = hashlib.sha256(salt_password).digest()
        hashed_password = base64.b64encode(hashed_password).decode('utf-8')

    payload = json.dumps({
        'server-passphrase-salt': salt,
        'server-passphrase': hashed_password,
        'has-asked-for-password-protection': 'true'
    })

    r = requests.patch(baseurl, headers=headers, cookies=cookies,
                       data=payload, verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code != 200:
        message = "Error updating password settings"
        common.log_output(message, True, r.status_code)
        return

    common.log_output("Updated password settings", True, 200)


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


# Get password by prompting user if no password was given in-line
def prompt_password(password, interactive):
    if password is None and interactive:
        common.log_output("Authentication required", False)
        password = getpass.getpass('Password:')
    elif password is None and not interactive:
        common.log_output("A password is required required", True)
        sys.exit(2)
    return password
