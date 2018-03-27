# Module for handling compatibility issues between OS'es and Python versions
import platform
import sys
import urllib
import os

from os.path import expanduser


# Use the correct directory for each OS
def get_config_location():
    home = expanduser("~")
    if platform.system() == 'Windows':
        config_dir = "/AppData/Local/DuplicatiClient/"
    else:
        config_dir = "/.config/duplicati-client/"

    config_file = home + config_dir + "config.yml"
    return config_file


# Clear terminal prompt
def clear_prompt():
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')


# Python 3 vs 2 urllib compatibility issues
def unquote(text):
    if sys.version_info[0] >= 3:
        return urllib.parse.unquote(text)
    else:
        return urllib.unquote(text)


# More urllib compatibility issues
def quote(text):
    if sys.version_info[0] >= 3:
        return urllib.parse.quote_plus(text)
    else:
        return urllib.quote_plus(text)
