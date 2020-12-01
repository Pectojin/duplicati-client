# Module for common functions used across multiple modules and functions
import auth
import config
import datetime
import io
import sys
import os.path
import urllib
import yaml
import compatibility

from dateutil import tz


# Common function for validating that required config fields are present
def validate_config(data):
    valid = True
    if "server" not in data:
        valid = False
    if "protocol" not in data.get("server", {}):
        valid = False
    if "url" not in data.get("server", {}):
        valid = False
    if "port" not in data.get("server", {}):
        valid = False
    if "token" not in data:
        valid = False
    if "token_expires" not in data:
        valid = False

    if not valid:
        message = "Configuration appears to be invalid. "
        message += "You can re-create it with 'duc config --overwrite'"
        log_output(message, True)
        sys.exit(2)


# Common function for writing config to file
def write_config(data):
    directory = os.path.dirname(config.CONFIG_FILE)
    if not os.path.exists(directory):
        message = "Created directory \"" + directory + "\""
        log_output(message, True)
        os.makedirs(directory)
    with io.open(config.CONFIG_FILE, 'w', encoding="UTF-8") as file:
        file.write(yaml.safe_dump(data, default_flow_style=False, allow_unicode=True))


# Common function for getting parameters from file
def load_parameters(data, args):
    # Check for parameters file
    file = data.get("parameters_file", None)
    if file is None:
        return args

    # Don't load nonexisting files
    if os.path.isfile(file) is False:
        return args

    # Load the parameters from the file
    with io.open(file, 'r', encoding="UTF-8") as file_handle:
        try:
            parameters_file = yaml.safe_load(file_handle)
            parameters = len(parameters_file)
            message = "Loaded " + str(parameters) + " parameters from file"
            log_output(message, True)

            for key, value in parameters_file.items():
                # Make sure not to override CLI provided arguments
                if args.get(key, None) is None:
                    args[key] = value

            # Verbose is special because verbose is a command not an argument
            if parameters_file.get("verbose", None) is not None:
                data["verbose"] = parameters_file.get("verbose")

            if parameters_file.get("precise", None) is not None:
                data["precise"] = parameters_file.get("precise")

            # Update parameters_file variable in config file
            data["parameters_file"] = file
            write_config(data)
            return args
        except yaml.YAMLError as exc:
            log_output(exc, True)
            return args


# Common function for logging messages
def log_output(text, important, code=None):
    # Determine whether the message should be displayed in stdout
    if config.VERBOSE is False and important is False:
        return
    if code is None or config.VERBOSE is False:
        print(text)
        return

    print(text + "\nCode: " + str(code))


# Common function for creating cookies to authenticate against the API
def create_cookies(data):
    token = data.get("token", "")
    if data.get("nonce", None) is None:
        return {
            "xsrf-token": token
        }

    nonce = data.get("nonce", "")
    session_auth = data.get("session-auth", "")
    return {
        "xsrf-token": token,
        "session-nonce": nonce,
        "session-auth": session_auth
    }


# Common function for creating headers to authenticate against the API
def create_headers(data):
    if data.get("token", None):
        headers = {
            "X-XSRF-TOKEN": data.get("token", "")
        }
    else:
        headers = None
    # Add a basic auth header if available
    basic_auth = data.get('authorization', '')
    if basic_auth != '':
        headers["Authorization"] = basic_auth

    return headers


# Common function for creating a base url
def create_baseurl(data, additional_path="", append_token=False):
    protocol = data["server"]["protocol"]
    url = data["server"]["url"]
    if protocol == "https" and data["server"]["port"] == "":
        port = "443"
    elif protocol == "http" and data["server"]["port"] == "":
        port = "8200"
    else:
        port = data["server"]["port"]
    baseurl = protocol + "://" + url + ":" + port + additional_path
    if append_token is True:
        baseurl += "?x-xsrf-token="
        baseurl += urllib.parse.quote_plus(data.get("token", ''))

    return baseurl


# Common function for checking API responses for session expiration
def check_response(data, status_code):
    # Exit if session expired
    if status_code == 400:
        message = "The server refused the request, "
        message += "you may need to login again"
        log_output(message, True)
        sys.exit(2)

    if status_code == 526:
        message = "Server certificate could not be validated. "
        log_output(message, True, status_code)
        message = "You can specify a certificate with --certfile "
        message += "or explicitly ignore this error with --insecure"
        log_output(message, True)
        sys.exit(2)

    if status_code == 495:
        message = "Provided certificate is invalid or "
        message += "does not match the server certificate"
        log_output(message, True)
        sys.exit(2)

    if status_code == 408:
        message = "The request timed out. "
        message += "Is the server running?"
        log_output(message, True)
        sys.exit(2)

    if status_code == 503:
        message = "Server is not responding. Is it running?"
        log_output(message, True, status_code)
        sys.exit(2)

    # Refresh token duration if request is OK
    if status_code == 200:
        expiration = datetime.datetime.now() + datetime.timedelta(0, 600)
        data["token_expires"] = expiration
        write_config(data)


# Common function for verifying token validity
def verify_token(data):
    token = data.get("token", None)
    expires = data.get("token_expires", None)
    if token is None or expires is None:
        log_output("Not logged in", True)
        sys.exit(2)

    # Get time
    now = datetime.datetime.now()

    # Take care of timezones
    now = now.replace(tzinfo=tz.tzutc())
    now = now.astimezone(tz.tzlocal())
    expires = expires.replace(tzinfo=tz.tzutc())
    expires = expires.astimezone(tz.tzlocal())

    # Check if token is still valid
    if now < expires:
        return

    # Try to log in again
    log_output("Token expired, trying to log in again", True)
    verify = data.get("server", {}).get("verify", True)
    args = load_parameters(data, {})
    password = args.get("password", None)
    if auth.login(data, password=password, verify=verify):
        return

    # Exit if token is invalid and an attempt to login failed
    sys.exit(2)


def ensure_trailing_slash(path):
    if path[-1] != "/":
        path += "/"
    return path


# Client intro
def info():
    return """Duplicati Client

Connect to Duplicati remotely or locally and manage them through the CLI.

To begin log into a server:
    duc login https://my.duplicati.server

or see --help to see information on usage
"""
