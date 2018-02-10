# Duplicati client
This client connects to Duplicati servers remotely or locally and helps manage them easily through the commandline.

A client daemon and cron mode is also available, allowing to periodically pull instructions from a central management server.

# Libraries used
Currently the script relies on multiple internal and external libraries:

    argparse
    requests
    urllib
    PyYaml
    json
    getpass
    hashlib
    datetime

# Installation
The client runs in either Python 3 or Python 2 but requires PyYaml and requests

    pip install pyyaml requests
Then you're ready to "install" the application, so clone the repo

    git clone https://github.com/pectojin/duplicati_client
The Python script should be executeable already, but for convenience you can symlink it

    ln -s /location/of/git/repo/duplicati.py /usr/bin/duplicati
On UNIX it should automatically attempt to use Python on your system so now you can just call

    duplicati
And you're good to go. 

# Usage
To begin log into a server:

    duplicati login https://my.duplicati.server
Then you can list resources

    duplicati list backups
Get info

    duplicati get backup 1
Run a backup job

    duplicati run backup 1
Logout when you're done

    duplicati logout

# Supported commands
    list      List all resources of a given type
    get       display breif information on one or many resources
    describe  display detailed information on a specific resource
    run       run a backup job
    edit      edit a resource on the server
    logs      display the logs for a given job
    login     log into a Duplicati server
    logout    end the current server session
    status    return information about the current session
    config    prints the config to stdout
    daemon    run Duplicati Client as a service

# Daemon mode
The Duplicati Client will eventually support Daemon mode. The Daemon mode will run in a continous loop and fetch a list of tasks to execute from it's "to-do list" server. On startup a server handling these to-do lists must be provided.
