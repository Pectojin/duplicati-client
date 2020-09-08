# Module for handling compatibility issues between OS'es and Python versions
import platform
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
