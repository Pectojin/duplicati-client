# Duplicati Client
The Duplicati Client connects to Duplicati servers remotely or locally and helps manage them easily through the command-line.

# Table of contents

<!--ts-->
   * [Why use Duplicati Client?](#why-use-duplicati-client)
   * [External libraries used](#external-libraries-used)
   * [Installation](#installation)
      * [From source](#from-source)
      * [Windows self contained binary](#windows-self-contained-binary)
      * [GNU/Linux and macOS self contained binaries](#gnulinux-and-macos-self-contained-binaries)
   * [Usage](#usage)
   * [Supported commands](#supported-commands)
   * [Setting the server password](#setting-the-server-password)
   * [Parameters file](#parameters-file)
   * [Export backups](#export-backups)
   * [Create and update backups](#create-and-update-backups)
<!--te-->

# Why use Duplicati Client?
Duplicati ships with a CommandLine tool that is capable of doing various actions like backups, restores, and verifying backend data.

However, the Duplicati CommandLine is a separate program. It does not communicate with the Duplicati Server that you interact with when using the web UI.

This plays out in various ways when trying to manually initiate a backup using the CommandLine tool and the Duplicati server not updating it's metadata or even showing that a backup is happening.

Additionally, the CommandLine is *stateless* in the sense that you need to provide all the relevant information each time you want to run a command. This can be daunting if you just want to initiate a backup run on an existing backup.

The Duplicati Client is a cross platform command-line tool that allows you to interact with the Duplicati Server as if you were using the web UI. It interacts with the same REST API as the web UI, which means it will behave the same and can be used from practically any machine that the web UI can be used from.

Furthermore, this tool makes it easy to write custom scripts for use in cron jobs or ad-hoc tasks. You can simply call the Client from your script or cron job as most options can be provided inline by the script. Even if your Duplicati Server is password protected your scripts can easily log in by using a parametersfile.

# External libraries used
Currently the script relies on multiple external libraries:

    requests
    PyYaml
    python-dateutil

# Installation
## From source
Clone the repo

    git clone https://github.com/pectojin/duplicati-client
The client runs on Python 3 and requires the above dependencies

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
    set       set values on resources
    run       run a backup job
    abort     abort a task
    create    create a resource on the server from a YAMl or JSON file
    update    update a resource on the server from a YAMl or JSON file
    delete    delete a backup
    export    export a backup from the server to YAMl or JSON format
    dismiss   dismiss notifications
    logs      display the logs for a given job
    login     log into a Duplicati server
    logout    end the current server session
    status    return information about the current session
    version   print version number
    config    prints the config to stdout
    verbose   Change between normal and verbose mode
    params    import parameters from a YAML file
    pause     pause Duplicati server
    resume    resume paused Duplicati server

Some of the commands are placeholders until I get them implemented.

# Setting the server password
It's possible to configure a server password using the `set password` command.

    duc set password

It will prompt for the new password and configure it on the server. You can also provide it inline using `--password` or using a parameters file.

You can disable the password using `--disable`

    duc set password --disable

Additionally, the `set password` command will remove the `password-protection` prompt ("If your machine is in a multi-user environment..."), so if you just want to pre-configure a system to remove that message you can make the `--disable` call to remove this message.

# Parameters file
Using the command `params` you can specify a parameters file. With this file you can provide most of the optional CLI arguments without having to specify them inline when calling your commands.

The parameters file is set once using the `params` command and then automatically loaded on each call.

You must create the parameters file yourself. An example of a parameters file:

    password: verysecretpassword
    verbose: True

Then specify that you want to use a parameters file

    duc params ~/.config/duplicati-client/parameters.yml

This will load your password, set verbose mode, and allow insecure connections by default when you run a command.

    Loaded 3 parameters from ~/.config/duplicati-client/parameters.yml

Then, if you're connecting to a different server, simply override the default password by adding the `--password` argument in the CLI.

    duc login localhost --password=othersecretpassword

Verbose is an exception to this rule. It applies session wide and can only be toggled by calling the `verbose` command, which is nonsensical if you have a parameters file enabling it again.

If you need to disable your parameters file, run

    duc params --disable

# Export backups
The export command enables building backup configuration files through the CLI. The Duplicati client will pull the necessary information on the selected backup and construct a configuration file. The configuration file can be exported in either YAML or JSON depending on preference

    duc export backup [id]

By default the client will export YAML, but you can manually specify either with `--output`. Additionally you can specify the output path with `--output-path`. You can also opt to export all backup configs using `--all`.

The resulting file can then be used to create new backup jobs with the import command. Notice that the JSON output is identical to exporting from the Duplicati Web UI, so if you need interoperability use JSON. The YAML file is only understood by this client for now.

Default options defined in settings are not exported with the job configuration.

# Create and update backups
The Create command allows creating backup jobs from a configuration file. Either a JSON file, as exported from the Duplicati Web UI, or a YAML/JSON file exported from this client. Input files are automatically converted into the JSON format that the Duplicati server requires, so it does not matter which format you import from.

    duc create backup [path_to_file]

By default metadata will not be imported, but if you'd like to retain the metadata use `--import-metadata`

The Update command allows updating an existing job from a configuration file.

    duc update backup [backup_id] [path_to_file]

Duplicati does not currently allow to update a backup configuration without also overwriting the metadata. If your config file was exported a long time ago with old metadata you may not be interested in this.

Apply the `--strip-metadata` option to remove the metadata before updating the backup config. This way no metadata will be displayed until the backup job has had a chance to run and provide the correct metadata.

Encrypted configuration files are currently not supported.

