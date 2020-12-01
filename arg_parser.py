import argparse as ap

# Initialize argument parser and standard optional arguments
parser = ap.ArgumentParser()

# Create subparsers
subparsers = parser.add_subparsers(title='commands', metavar="", help="")

# Subparser for the List method
message = "list all resources of a given type"
list_parser = subparsers.add_parser('list', help=message)
choices = [
    "backups",
    "databases",
    "restores",
    "notifications",
    "serversettings",
    "systeminfo"
]
message = "the type of resource"
list_parser.add_argument('type', choices=choices, help=message)

# Subparser for the Get method
message = "display breif information on one or many resources"
get_parser = subparsers.add_parser('get', help=message)
message = "the type of resource"
choices = ["backup", "notification"]
get_parser.add_argument('type', choices=choices, help=message)
message = "one or more ID's to look up"
get_parser.add_argument('id', nargs='+', type=int, help=message)

# Subparser for the Describe method
message = "display detailed information on a specific resource"
describe_parser = subparsers.add_parser('describe', help=message)
message = "the type of resource"
choices = [
    "backup",
    "notification"
]
describe_parser.add_argument('type', choices=choices, help=message)
message = "the ID of the resource to look up"
describe_parser.add_argument('id', nargs='+', type=int, help=message)

# Subparser for the set method
message = "set values on resources"
set_parser = subparsers.add_parser('set', help=message)
message = "control password protection of the server"
set_subparser = set_parser.add_subparsers(title='set', metavar="", help="")
message = "set or disable the server password"
set_pwd_parser = set_subparser.add_parser('password', help=message)
message = "disable the server password"
set_pwd_parser.add_argument('--disable', help=message, action='store_true')
message = "provide a password inline instead of interactively"
set_pwd_parser.add_argument('--password', metavar='', help=message)
message = "noninteractive mode for use in scripts"
set_pwd_parser.add_argument('--script', action='store_false', help=message)


# Subparser for the Run method
message = "run a backup job"
run_parser = subparsers.add_parser('run', help=message)
message = "the ID of the backup job to run"
run_parser.add_argument('id', type=int, help=message)

# Subparser for the Abort method
message = "abort a task"
abort_parser = subparsers.add_parser('abort', help=message)
message = "the ID of the task to abort"
abort_parser.add_argument('id', type=int, help=message)

# Subparser for the Create method
message = "create a resource on the server from a YAMl or JSON file"
create_parser = subparsers.add_parser('create', help=message)
message = "the type of resource"
create_parser.add_argument('type', choices=["backup"], help=message)
message = "file containing a job configuration in YAML or JSON format"
create_parser.add_argument('import-file', nargs='?', help=message)
message = "import the metadata when creating a backup"
create_parser.add_argument('--import-metadata', help=message,
                           action='store_true')

# Subparser for the Update method
message = "update a resource on the server from a YAMl or JSON file"
update_parser = subparsers.add_parser('update', help=message)
message = "the type of resource"
update_parser.add_argument('type', choices=["backup"], help=message)
message = "the ID of the resource to update"
update_parser.add_argument('id', help=message)
message = "file containing a job configuration in YAML or JSON format"
update_parser.add_argument('import-file', nargs='?', help=message)
message = "strip metadata before updating the resource"
update_parser.add_argument('--strip-metadata', help=message,
                           action='store_true')

# Subparser for the Delete method
message = "delete a resource on the server"
delete_parser = subparsers.add_parser('delete', help=message)
choices = ["backup", "notification", "database"]
message = "the type of resource"
delete_parser.add_argument('type', choices=choices, help=message)
message = "the ID of the resource to delete"
delete_parser.add_argument('id', type=int, help=message)
# message = "delete the local database"
# delete_parser.add_argument('--delete-db',
#                            action='store_true', help=message)
message = "confirm deletion non-interactively"
delete_parser.add_argument('--confirm',
                           action='store_true', help=message)
message = "recreate database after deletion"
delete_parser.add_argument('--recreate',
                           action='store_true', help=message)

# Subparser for the Edit method
# message = "edit a resource on the server"
# edit_parser = subparsers.add_parser('edit', help=message)
# message = "the type of resource"
# edit_parser.add_argument('type', help=message)
# message = "the ID of the resource to edit"
# edit_parser.add_argument('id', type=int, help=message)

# Subparser for the Export method
message = "export a backup from the server to YAMl or JSON format"
export_parser = subparsers.add_parser('export', help=message)
message = "the ID of the resource to export"
export_parser.add_argument('id', action='store', nargs='?', type=int, help=message)
message = "export all backups"
export_parser.add_argument('--all', action='store_true', help=message)
message = "timestamp the exported file"
export_parser.add_argument('--timestamp', action='store_true', help=message)
choices = [
    "YAML",
    "JSON",
    "yaml",
    "json"
]
message = "output YAML or JSON, defaults to JSON"
export_parser.add_argument('--output', help=message,
                           choices=choices, metavar='')
message = "path to output the file at"
export_parser.add_argument('--output-path', metavar='', help=message)
message = "avoid having passwords in the exported config"
export_parser.add_argument('--no-passwords', action='store_false', help=message)


# Subparser for the Repair method
message = "repair a database"
repair_parser = subparsers.add_parser('repair', help=message)
message = "backup database to repair"
repair_parser.add_argument('id', help=message)

# Subparser for the Vacuum method
message = "vacuum a database"
repair_parser = subparsers.add_parser('vacuum', help=message)
message = "backup database to vacuum"
repair_parser.add_argument('id', help=message)

# Subparser for the Verify method
message = "verify remote backup data"
repair_parser = subparsers.add_parser('verify', help=message)
message = "backup to verify"
repair_parser.add_argument('id', help=message)

# Subparser for the Compact method
message = "compact remote backup data"
repair_parser = subparsers.add_parser('compact', help=message)
message = "backup to compact"
repair_parser.add_argument('id', help=message)


# Subparser for the Dismiss method
message = "dismiss notifications"
dismiss_parser = subparsers.add_parser('dismiss', help=message)
message = "dismiss one or all notifications"
dismiss_parser.add_argument('id', metavar='{id, all}', help=message)

# Subparser for the Logs method
message = "display the logs for a given job"
logs_parser = subparsers.add_parser('logs', help=message)
choices = [
    "backup",
    "stored",
    "profiling",
    "information",
    "warning",
    "error"
]
message = "backup, stored, profiling, information, warning, or error"
logs_parser.add_argument('type', metavar='type',
                         choices=choices, help=message)
message = "backup id"
logs_parser.add_argument('--id', type=int, metavar='', help=message)
message = "view backend logs for the backup job"
logs_parser.add_argument('--remote', action='store_true', help=message)
message = "periodically pool for new logs until interrupted"
logs_parser.add_argument('--follow', action='store_true', help=message)
message = "log lines to display"
logs_parser.add_argument('--lines', action='store', default=5,
                         type=int, metavar='', help=message)
message = "show all message and exception lines"
logs_parser.add_argument('--all', action='store_true', help=message)

# Subparser for the Login method
message = "log into a Duplicati server"
login_parser = subparsers.add_parser('login', help=message)
login_parser.add_argument('url', nargs='?')
message = "provide a password inline instead of interactively"
login_parser.add_argument('--password', metavar='', help=message)
message = "username to use for basic auth"
login_parser.add_argument('--basic-user', metavar='', help=message)
message = "password to use for basic auth"
login_parser.add_argument('--basic-pass', metavar='', help=message)
message = "allow insecure HTTPS connections to the server"
login_parser.add_argument('--insecure', action='store_true', help=message)
message = "specify the path to certificate to be used for validation"
login_parser.add_argument('--certfile', metavar='', help=message)
message = "noninteractive mode for use in scripts"
login_parser.add_argument('--script', action='store_false', help=message)

# Subparser for the Logout method
message = "end the current server session"
subparsers.add_parser('logout', help=message)

# Subparser for the Status method
message = "print information about the current session"
subparsers.add_parser('status', help=message)

# Subparser for the Version method
message = "print version number"
subparsers.add_parser('version', help=message)

# Subparser for the Config method
message = "print the config"
config_parser = subparsers.add_parser('config', help=message)
message = "create a new configuration"
config_parser.add_argument('--overwrite', action='store_true',
                           help=message)

# Subparser for the Daemon mode
# message = "run as a service"
# subparsers.add_parser('daemon', help=message)

# Subparser for toggling verbose mode
message = "change between normal and verbose mode"
verbose_parser = subparsers.add_parser('verbose', help=message)
choices = ["enable", "disable"]
verbose_parser.add_argument('mode', nargs='?', choices=choices)

# Subparser for toggling precise time mode
message = "change between short and precise time format"
precise_parser = subparsers.add_parser('precise', help=message)
choices = ["enable", "disable"]
precise_parser.add_argument('mode', nargs='?', choices=choices)

# Subparser for setting a parameter file
message = "import parameters from a YAML file"
params_parser = subparsers.add_parser('params', help=message)
message = "path to file containing parameters in YAML format"
params_parser.add_argument('param-file', nargs='?', help=message)
message = "disable the parameters file"
params_parser.add_argument('--disable', help=message, action='store_true')
params_parser.add_argument('--show', help=message, action='store_true')

# Subparser for pause
message = "pause Duplicati server"
pause_parser = subparsers.add_parser('pause', help=message)
message = "duration before resume (e.g. 5m, 1h or empty for unlimited)"
pause_parser.add_argument('--duration', default="", help=message)

# Subparser for resume
message = "resume paused Duplicati server"
resume_parser = subparsers.add_parser('resume', help=message)

