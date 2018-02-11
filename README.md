# Duplicati client
This client connects to Duplicati servers remotely or locally and helps manage them easily through the commandline.

A client daemon and cron mode is also available, allowing to periodically pull instructions from a central management server.

# Libraries used
Currently the script relies on multiple internal and external libraries:

    argparse
    os.path
    requests
    urllib
    PyYaml
    getpass
    hashlib
    base64
    datetime
    python-dateutil

# Installation
The client runs in either Python 3 or Python 2 but requires PyYaml and requests

    pip install pyyaml requests python-dateutil
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

# Supported commands (some placeholders until I get it working)
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
The Duplicati Client will eventually support daemon mode. The daemon mode will run in a continous loop and fetch a list of tasks to execute from it's "task list" server. On startup a task server must be provided.

# Task server API specification
The task server, that daemon mode communicates with, must support the following REST methods:

## Status
    api/tasks/status
Returns an empty response with HTTP status code `303` or `304`.

`303` makes the daemon to fetch the task list

`304` makes the daemon to wait until next pool interval

The task server must keep track of this state internally and toggle to 303 when it has tasks that have not been "accepted" or "refused" by the Daemon

## Task list
    api/tasks
Returns a JSON object with a list of tasks to be executed by the daemon.

The format must be as follows:

    {
        "ID": 1,                 # An ID defined by the Task server. Must be unique within 'daemon session'
        "Operation": "get",      # Any operation supported by the client and not prohibited by client policy
        "Resources": [           # List containing one or more resources
            {
                "Type": backup",     # The resource type
                "ID": 3              # The resource id
            }
        ]
    }
Notice that ID and Operation are required fields. The remaining fields depend on the operation called. See client `--help` or the docs when I complete them.

## Result destination
    api/tasks/<id>/result
Accepts a JSON object from the daemon describing the result of a task and containing any requested information

Format:

    {
        "ID": 1,
        "Status": "completed"         # accepted, refused, completed, error
        "Data": {
            "some": "json_result"
        }
    }

Must return `200` OK or the daemon will retry later

## Notes
The daemon will have a configuration options to override the API url, but anything after `api/` must be present.

To support daemon durability each task is logged into a `task-list.yml` on disk allowing the daemon to recover from crashes. This file is periodically updated with status on each task. 

When the daemon fetches the task list it will validate each task and inform the task server whether each task was accepted or rejected. 

The daemon may execute a task immediately, skipping the accepted/rejected update.

Items with invalid formatting and items prohibited by policy are rejected.

Once a task has been completed the daemon sends the result to the server and confirms that the server received the data. 

The task is then removed from the list local task list.

