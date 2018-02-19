# Duplicati client
Version 0.1.17 alpha

## 0.1.17 alpha (021f0be)
Added logging functionality. Supports showing backup logs, remote logs, stored logs, and each level of live logs (profiling, information, warning, error). Also provides a `--follow` mode that will periodically pull new logs from the server.

Updated parameters command to work *like* the config command when no input is provided.

Added speed indicator to the get backup command output

Updated config command to provide expiration information and configuration file path

Updated the list backups command to show breif progress information on running jobs

Improved consistency in internal token expiration tracking

Various bug fixes

## 0.1.5 alpha (d8f3007)
Added delete command to allow deleting backups

Improved filter on the backup get command to provide better information

Added some type checks to fail early on bad input


## 0.1.3 alpha (f248a4e)
Added a `--show` argument to the params command to allow viewing parameters without navigating the file

Improved URL parsing on login to handle many more cases including omitting invalid characters and substituting missing fields with default values

## 0.1.1 alpha (7984e98)
Fixed an issue with the file name of exported backup configurations beign invalid on windows

## 0.1.0 alpha (fec0cb7)
Major overhaul of code style to improve readability and adhere to PEP8 style guide.

Added local token expiration checks

Consolidated token verification in single function

Added get and describe functionality for notifications

## 0.0.4 notes (b485e99)
Fixed an issue with the get command not printing the resource after fetching it from the server

## 0.0.3 notes (0321670)
Import and export config files to create new backups

## 0.0.2 notes (4f291ce)
Login to password protected servers

Add parameters file to persist settings throughout session

Drafted first version of the Daemon API server specification

## 0.0.1 notes (5548ef3)
List backups, notifications, serversettings, and systeminfo

Get info on one or more backups

Describe all info on a backup

Start and abort backup jobs

Login to unprotected servers
