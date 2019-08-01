# Duplicati client
Version 0.4.21 beta

## 0.4.21 beta (20c7c27)

Fixed an issue with the client not being able to connect to ports other than 443 when using HTTPS.

## 0.4.20 beta (346e97c)

Added support for the new Vacuum API command - Thanks @drwtsn32x

Corrected error handling of list command when encountering no entries

Added preliminary support for exporting serversettings

Added server url to status printout

Made timestamp optional in filename when exporting backups

## 0.4.15 beta (72243a2)

Added timeouts on Requests calls to avoid hanging forever on servers not responding

Added an --all option to export

Changed --output-path to specify the directory, but not the name, in order to be compatible with --all

Removed progress info on get and describe commands against backups that have finished to avoid confusion.

Changed describe method to allow providing multiple ID's

Fixed an issue where calling get with multiple ID's broke the duc config

## 0.4.9 beta (fd61f6c)

Fixed an issue where wrong dates were displayed for last backup.

Added support for initializing compact on a backup database

Added support for initializing remote data verification on backup

Added support for listing, deleting, repairing, and recreating backup databases

Added server status to the status command

Made the backup list and get commands only display progress when a backup is running

## 0.3.16 beta (ad809c7)

Fixed an issue with authentication affecting some platforms, such as Alpine Linux, thanks to @mjmayer

Fixed an edge case with the client exiting when both basic auth and duplicati password was provided, thanks to @mjmayer

Unit tests of the login and check_response methods, thanks to @mjmayer

Small update the the build scripts for MacOS and Linux

## 0.3.12 beta (b25d8a7)

Added a 'set password' command allowing to enable or disable the server password and removing the 'password-protection' prompt on new installations

Updated the requests wrapper to incldue a patch method

Removed the deprecated 'import' command

## 0.3.9 beta (dbcbfed)

Fixed a namespacing issue preventing the client binary from running on windows

## 0.3.8 beta (da02b4a)

Added support for basic authentication (e.g. through a reverse proxy). Can be used with the `--basic-user` and `--basic-pass` parameters inline, in the params file, or interactively.

Added `processed data` field to the get command output to display along with the `processed files`

Refactored the client code base into smaller more manageable modules

Updated the create/update/import commands to better parse import errors provided by the Duplicati server

Added --script argument to the login command to prevent interactive prompts in scripts

Fixed a problem with timestamp parsing errors

## 0.2.15 beta (c5a437e)
Updated config file path to be canonical on Windows (`%APPDATA%/Local/DuplicatiClient`) and Linux (`~/.config/duplicati-client`).

Added support for connecting to server over HTTPS. Implemented logic and error handling for invalid certificates along with `--insecure` and `--certfile` options to allow using private or self signed certificates.

Added user confirmation step when deleting backup jobs.

Added validation step to check if backup exists before trying to delete it.

Updated the Verbose command to support explicitly declaring `enable` or `disable` instead of only allowing toggling.

Changed from verbose mode to nonverbose mode on default.

Added success message on successful login.

Updated the filter on `list serversettings` to make it more readable.

Fixed a problem with login not exiting after failing to authenticate.

Added Create and Update commands to be used in place of the Import command. The Import command will be deprecated due to it's confusing syntax.

Updated the Delete command to allow deleting notifications as well as backup jobs.

Added a Dismiss command as a shortcut for deleting notifications and as a way to dismiss all notifications at once.

Updated all commands to attempt logging in again if they're called with an expired token.

Improved robustness of the Login command.

Updated the Login command to allow defaulting to last provided URL when no URL is provided.

Added script for packaging a general Python release.

## 0.1.26 alpha (76075a8)
Improved error handling when attempting to connect to a server that does not respond

Updated the Import method to allow updating an existing backup from a configuration file

Added configuration validation

Added an option to overwrite the config file from within the client

Fixed a bug where dates less than 24 hours in the past would be displayed as "Tomorrow"

Fixed a bug where the client would abort when attempting to print backup info while the backup was running but not transferring data.

Added build scripts for Windows, macOS, and GNU/Linux to ease the creation of self contained binaries for each platform

## 0.1.18 alpha (cd2fc93)
Fixed an issue where logging in would not refresh the expiration token.

Changed the expiration token to be an expression of when the token expires instead of when it was renewed

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
