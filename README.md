# Duplicati client
This client connects to Duplicati servers remotely or locally and helps manage them easily through the commandline.

A client daemon mode will be available eventually, allowing to periodically pull instructions from a central management server.

# External libraries used
Currently the script relies on multiple external libraries:

    requests
    PyYaml
    python-dateutil

# Installation
## From source
Clone the repo

    git clone https://github.com/pectojin/duplicati_client
The client runs in either Python 3 or Python 2 but requires the above dependencies

    pip3 install -r requirements.txt
For convenience you can symlink the client

    sudo ln -s /location/of/git/repo/duplicati_client.py /usr/bin/duc
On UNIX it should automatically attempt to use Python on your system so now you can just call

    duc
And you're good to go. 

## Windows self contained binary
For installation of the Windows self contained binary package I recommend copying it to `C:\Program Files\Duplicati Client` and then adding that path to your [environment variable path](https://www.computerhope.com/issues/ch000549.htm) so that you can call `duplicati_client` from anywhere in your CLI.

## GNU/Linux and macOS self contained binaries
Self contained binaries are also available for Linux and macOS. 

These are useful if you cannot or will not install the 3rd party dependencies on your system, or if you experience compatibility problems with your current Python installation.

I recommend copying the binary package to `/opt/duplicati_client` on Linux and `/Applications/Duplicati Client` on macOS. Then symlink the duplicati_client binary

    sudo ln -s /location/of/duplicati_client /usr/bin/duc

# Usage
To begin log into a server:

    duc login https://my.duplicati.server
Then you can list resources

    duc list backups
Get info

    duc get backup 1
Run a backup job

    duc run backup 1
Logout when you're done

    duc logout

# Supported commands
    list      List all resources of a given type
    get       display breif information on one or many resources
    describe  display detailed information on a specific resource
    run       run a backup job
    abort     abort a task
    delete    delete a backup
    edit      edit a resource on the server
    export    export a resource from the server to YAMl or JSON format
    import    import a resource to the server from a YAMl or JSON file
    logs      display the logs for a given job
    login     log into a Duplicati server
    logout    end the current server session
    status    return information about the current session
    config    prints the config to stdout
    daemon    run Duplicati Client as a service
    verbose   toggle verbose mode
    params    import parameters from a YAML file

Some of the commands are placeholders until I get them implemented.

# Parameters file
Using the command `params` you can specify a parameters file. With this file you can provide most of the optional CLI arguments without having to specify them inline when calling your commands.

The parameters file is set once using the `params` command and then automatically loaded on each call.

You must create the parameters file yourself. An example of a parameters file:
    
    password: verysecretpassword
    verbose: True

Then specify that you want to use a parameters file

    duc params ~/.config/duplicati_client/parameters.yml

This will load your password, set verbose mode, and allow insecure connections by default when you run a command.

    Loaded 3 parameters from ~/.config/duplicati_client/parameters.yml

Then, if you're connecting to a different server, simply override the default password by adding the `--password` argument in the CLI.

    duc login localhost --password=othersecretpassword

Verbose is an exception to this rule. It applies session wide and can only be toggled by calling the `verbose` command, which is nonsensical if you have a parameters file enabling it again.

If you need to disable your parameters file, run

    duc params --disable

# Export backups
The export command enables building backup configuration files through the CLI. The Duplicati client will pull the necessary information on the selected backup and construct a configuration file. The configuration file can be exported in either YAML or JSON depending on preference

    duc export backup [id]

By default the client will export YAML, but you can manually specify either with `--output`. Additionally you can specify the output path with `--output-path`.

The resulting file can then be used to create new backup jobs with the import command. Notice that the JSON output is identical to exporting from the Duplicati Web UI, so if you need interoperability use JSON. The YAML file is only understood by this client for now.

# Import backups
The import command enables creating new backup configurations from a configuration file. Use either a JSON file exported from the Duplicati Web UI or a YAML/JSON file exported from this client. Input files are automatically converted into the JSON format that the Duplicati server requires, so it does not matter which format you import from.

    duc import backup [path_to_file]

By default metadata will not be imported, but if you'd like to retain the metadata use `--import-metadata`

You can also import the configuration over an existing job to update the job. Simply use the `--id` parameter to update a backup configuration.

    duc import backup [path_to_file] --id=<backup_id>

Duplicati does not currently allow to update a backup configuration without also overwriting the metadata. If your config file was exported a long time ago with old metadata you may not be interested in this. 

Apply the `--strip-metadata` option to remove the metadata before updating the backup config. This way the metadata will not be displayed until the backup job has had a chance to run and provide the correct metadata.

Encrypted configuration files are currently not supported.

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

