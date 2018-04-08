#!/usr/bin/env python3
import parser as ArgumentParser
import config
import json
import os.path
import sys
import datetime
import time
import yaml
import compatibility
import common
import auth
import helper

from os.path import expanduser
from os.path import splitext
from requests_wrapper import requests_wrapper as requests


def main(**args):
    # Command method
    method = sys.argv[1]

    if method == "version":
        message = "Duplicati client version "
        message += config.APPLICATION_VERSION
        return common.log_output(message, True)

    # Default values
    data = {
        "last_login": None,
        "parameters_file": None,
        "server": {
            "port": "8200",
            "protocol": "http",
            "url": "localhost",
            "verify": True
        },
        'token': None,
        'token_expires': None,
        'verbose': False,
        'authorization': ''
    }

    # Detect home dir for config file
    config.CONFIG_FILE = compatibility.get_config_location()

    # Load configuration
    overwrite = args.get("overwrite", False)
    data = load_config(data, overwrite)

    param_file = args.get("param-file", None)
    # Set parameters file
    if method == "params":
        data = set_parameters_file(data, args, param_file)

    # Load parameters file
    args = common.load_parameters(data, args)

    # Show parameters
    if method == "params" and (args.get("show", False) or param_file is None):
        display_parameters(data)

    # Toggle verbosity
    if method == "verbose":
        mode = args.get("mode", None)
        data = toggle_verbose(data, mode)

    # Write verbosity setting to config variable
    config.VERBOSE = data.get("verbose", False)

    # Display the config if requested
    if method == "config":
        display_config(data)

    # Display the status if requested
    if method == "status":
        display_status(data)

    # Login
    if method == "login":
        url = args.get("url", None)
        password = args.get("password", None)
        basic_user = args.get("basic_user", None)
        basic_pass = args.get("basic_pass", None)
        certfile = args.get("certfile", None)
        insecure = args.get("insecure", False)
        verify = auth.determine_ssl_validation(data, certfile, insecure)
        interactive = args.get("script", True)
        data = auth.login(data, url, password, verify, interactive, basic_user, basic_pass)

    # Logout
    if method == "logout":
        data = auth.logout(data)

    # List resources
    if method == "list":
        resource_type = args.get("type", None)
        list_resources(data, resource_type)

    # Get resources
    if method == "get":
        resource_type = args.get("type", None)
        resource_id = args.get("id", None)
        get_resources(data, resource_type, resource_id)

    # Get resources
    if method == "describe":
        resource_type = args.get("type", None)
        resource_id = args.get("id", None)
        describe_resource(data, resource_type, resource_id)

    # Dismiss notifications
    if method == "dismiss":
        resource_id = args.get("id", "all")
        if not resource_id.isdigit() and resource_id != "all":
            common.log_output("Invalid id: " + resource_id, True)
            return
        dismiss_notifications(data, resource_id)

    # Show logs
    if method == "logs":
        log_type = args.get("type", None)
        backup_id = args.get("id", None)
        remote = args.get("remote", False)
        follow = args.get("follow", False)
        lines = args.get("lines", 10)
        show_all = args.get("all", False)
        get_logs(data, log_type, backup_id, remote, follow, lines, show_all)

    # Run backup
    if method == "run":
        backup_id = args.get("id", None)
        run_backup(data, backup_id)

    # Abort backup
    if method == "abort":
        backup_id = args.get("id", None)
        abort_task(data, backup_id)

    # Create method
    if method == "create":
        import_type = args.get("type", None)
        import_file = args.get("import-file", None)
        import_meta = args.get("import_metadata", None)

        import_resource(data, import_type, import_file, None, import_meta)

    # Update method
    if method == "update":
        import_type = args.get("type", None)
        import_id = args.get("id", None)
        import_file = args.get("import-file", None)
        # import-metadata is the inverse of strip-metadata
        import_meta = not args.get("strip_metadata", False)

        import_resource(data, import_type, import_file, import_id, import_meta)

    # Delete a resource
    if method == "delete":
        resource_id = args.get("id", None)
        resource_type = args.get("type", None)
        delete_db = args.get("delete_db", False)
        confirm = args.get("confirm", False)
        delete_resource(data, resource_type, resource_id, confirm, delete_db)

    # Import method
    if method == "import":
        message = "DEPRECATED: Consider using Create or Update instead"
        common.log_output(message, True)
        import_type = args.get("type", None)
        import_file = args.get("import-file", None)
        import_id = args.get("id", None)
        import_meta = args.get("import_metadata", None)
        strip_meta = args.get("strip_metadata", False)
        # Strip meta data is only valid when import_id is specified
        if import_id is not None and not strip_meta:
            import_meta = True

        import_resource(data, import_type, import_file, import_id, import_meta)

    # Export method
    if method == "export":
        resource_type = args.get("type", None)
        resource_id = args.get("id", None)
        output_type = args.get("output", None)
        path = args.get("output_path", None)
        export_resource(data, resource_type, resource_id, output_type, path)


# Function for display a list of resources
def list_resources(data, resource):
    common.verify_token(data)

    if resource == "backups":
        resource_list = fetch_backup_list(data)
    else:
        resource_list = fetch_resource_list(data, resource)

    resource_list = list_filter(resource_list, resource)

    if len(resource_list) == 0:
        common.log_output("No items found", True)
        sys.exit(2)

    # Must use safe_dump for python 2 compatibility
    message = yaml.safe_dump(resource_list, default_flow_style=False)
    common.log_output(message, True, 200)


# Fetch all backups
def fetch_backup_list(data):
    backups = fetch_resource_list(data, "backups")

    # Fetch progress state
    progress_state, active_id = fetch_progress_state(data)

    backup_list = []
    for backup in backups:
        backup_id = backup.get("Backup", {}).get("ID", 0)
        if active_id is not None and backup_id == active_id:
            backup["Progress"] = progress_state
        backup_list.append(backup)

    return backup_list


# Fetch all resources of a certain type
def fetch_resource_list(data, resource):
    baseurl = common.create_baseurl(data, "/api/v1/" + resource)
    common.log_output("Fetching " + resource + " list from API...", False)
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    r = requests.get(baseurl, headers=headers, cookies=cookies, verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code != 200:
        common.log_output("Error connecting", True, r.status_code)
        sys.exit(2)
    else:
        return r.json()


# Filter logic for the list function to facilitate readable output
def list_filter(json_input, resource):
    resource_list = []
    if resource == "backups":
        for key in json_input:
            backup = key.get("Backup", None)
            schedule = key.get("Schedule", None)
            progress_state = key.get("Progress", None)
            backup_name = backup.get("Name", "")
            backup = {
                backup_name: {
                    "ID": backup.get("ID", ""),
                }
            }

            if backup.get('Metadata', {}).get('SourceSizeString') is not None:
                size = backup.get('Metadata', {}).get('SourceSizeString')
                backup[backup_name]["Source size"] = size

            if schedule is not None:
                next_run = helper.format_time(schedule.get("Time", ""))
                if next_run is not None:
                    backup[backup_name]["Next run"] = next_run

                last_run = helper.format_time(schedule.get("LastRun", ""))
                if last_run is not None:
                    backup[backup_name]["Last run"] = last_run

            if progress_state is not None:
                backup[backup_name]["Running"] = {
                    "Task ID": progress_state.get("TaskID", None),
                    "State": progress_state.get("Phase", None),
                }

            resource_list.append(backup)

    elif resource == "notifications":
        for val in json_input:
            notification = {
                val.get("Title", ""): {
                    "Backup ID": val.get("BackupID", ""),
                    "Notification ID": val.get("ID", ""),
                }
            }
            timestamp = helper.format_time(val.get("Timestamp", ""))
            if timestamp is not None:
                notification["Timestamp"] = timestamp

            resource_list.append(notification)

    elif resource == "serversettings":
        for key, value in json_input.items():
            if key == "update-check-latest":
                continue
            setting = {
                key: {
                    "value": value
                }
            }

            resource_list.append(setting)
    else:
        resource_list = json_input

    return resource_list


# Get one or more resources with somewhat limited fields
def get_resources(data, resource_type, resource_id):
    if resource_type == "backup":
        result = fetch_backups(data, resource_id, "get")
    elif resource_type == "notification":
        result = fetch_notifications(data, resource_id, "get")

    message = yaml.safe_dump(result, default_flow_style=False)
    common.log_output(message, True, 200)


# Get one resource with all fields
def describe_resource(data, resource_type, resource_id):
    if resource_type == "backup":
        result = fetch_backups(data, [resource_id], "describe")
    elif resource_type == "notification":
        result = fetch_notifications(data, [resource_id], "describe")

    # Must use safe_dump for python 2 compatibility
    message = yaml.safe_dump(result, default_flow_style=False)
    common.log_output(message, True, 200)


# Fetch notifications
def fetch_notifications(data, notification_ids, method):
    common.verify_token(data)

    common.log_output("Fetching notifications from API...", False)
    baseurl = common.create_baseurl(data, "/api/v1/notifications")
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    notification_list = []
    r = requests.get(baseurl, headers=headers, cookies=cookies, verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code != 200:
        id_list = ', '.join(notification_ids)
        message = "Error getting notifications " + id_list
        common.log_output(message, True, r.status_code)
    else:
        data = r.json()

    for notification in data:
        notification_id = notification.get("ID", -1)
        if str(notification_id) in notification_ids:
            notification_list.append(notification)

    # Only get uses a filter
    if method == "get":
        notification_list = notification_filter(notification_list)

    return notification_list


# Filter logic for the notification get command
def notification_filter(json_input):
    notification_list = []
    for key in json_input:
        title = key.get("Title", "Notification")
        notification = {
            title: {
                "Backup ID": key.get("BackupID", ""),
                "Notification ID": key.get("ID", ""),
                "Message": key.get("Message", ""),
                "Type": key.get("Type", ""),
            }
        }
        timestamp = helper.format_time(key.get("Timestamp", ""))
        if timestamp is not None:
            notification[title]["Timestamp"] = timestamp

        notification_list.append(notification)

    return notification_list


# Fetch backups
def fetch_backups(data, backup_ids, method):
    common.verify_token(data)

    common.log_output("Fetching backups from API...", False)
    progress_state, active_id = fetch_progress_state(data)
    backup_list = []
    baseurl = common.create_baseurl(data, "/api/v1/backup/")
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    # Iterate over backup_ids and fetch their info
    for backup_id in backup_ids:
        r = requests.get(baseurl + str(backup_id), headers=headers,
                         cookies=cookies, verify=verify)
        common.check_response(data, r.status_code)
        if r.status_code != 200:
            message = "Error getting backup " + str(backup_id)
            common.log_output(message, True, r.status_code)
            continue
        data = r.json()["data"]

        item_id = data.get("Backup", {}).get("ID", 0)
        if active_id is not None and item_id == active_id:
            data["Progress"] = progress_state
        backup_list.append(data)

    if len(backup_list) == 0:
        sys.exit(2)

    # Only get uses a filter
    if method == "get":
        backup_list = backup_filter(backup_list)

    return backup_list


# Fetch backup progress state
def fetch_progress_state(data):
    baseurl = common.create_baseurl(data, "/api/v1/progressstate")
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    # Check progress state and get info for the running backup
    r = requests.get(baseurl, headers=headers, cookies=cookies, verify=verify)
    if r.status_code != 200:
        active_id = -1
        progress_state = {}
    else:
        progress_state = r.json()
        active_id = progress_state.get("BackupID", -1)

    return progress_state, active_id


# Filter logic for the fetch backup/backups methods
def backup_filter(json_input):
    backup_list = []
    for key in json_input:
        backup = key.pop("Backup", {})
        metadata = backup.pop("Metadata", {})
        backup_name = backup.pop("Name", {})
        backup = {
            "ID": backup.get("ID", ""),
            "Local database": backup.get("DBPath", ""),
        }
        backup["Versions"] = int(metadata.get("BackupListCount", 0))
        backup["Last run"] = {
            "Duration":
            helper.format_duration(metadata.get("LastDuration", "0")),
            "Started":
            helper.format_time(metadata.get("LastStarted", "0")),
            "Stopped":
            helper.format_time(metadata.get("LastFinished", "0")),
        }
        backup["Size"] = {
            "Local": metadata.get("SourceSizeString", ""),
            "Backend": metadata.get("TargetSizeString", "")
        }

        schedule = key.get("Schedule", None)
        if schedule is not None:
            next_run = helper.format_time(schedule.pop("Time", ""))
            if next_run is not None:
                schedule["Next run"] = next_run
            last_run = helper.format_time(schedule.pop("LastRun", ""))
            if last_run is not None:
                schedule["Last run"] = last_run
            schedule.pop("AllowedDays", None)
            schedule.pop("ID", None)
            schedule.pop("Rule", None)
            schedule.pop("Tags", None)

        progress_state = key.get("Progress", {})
        state = progress_state.get("Phase", None)
        speed = progress_state.get("BackendSpeed", 0)
        progress = {
            "State": state,
            "Counting files": progress_state.get("StillCounting", False),
            "Backend": {
                "Action": progress_state.get("BackendAction", 0)
            },
            "Task ID": progress_state.get("TaskID", -1),
        }
        if speed > 0:
            progress["Backend"]["Speed"] = helper.format_bytes(speed) + "/s"

        # Display item only if relevant
        if not progress_state.get("StillCounting", False):
            progress.pop("Counting files")
        # Avoid 0 division
        file_count = progress_state.get("ProcessedFileCount", 0)
        total_file_count = progress_state.get("TotalFileCount", 0)
        processing = state == "Backup_ProcessingFiles"
        if file_count > 0 and total_file_count > 0 and processing:
            processed = "{0:.2f}".format(file_count / total_file_count * 100)
            progress["Processed files"] = processed + "%"
        # Avoid 0 division
        data_size = progress_state.get("ProcessedFileSize", 0)
        total_data_size = progress_state.get("TotalFileSize", 0)
        processing = state == "Backup_ProcessingFiles"
        if data_size > 0 and total_data_size > 0 and processing:
            # Calculate percentage
            processed = "{0:.2f}".format(data_size / total_data_size * 100)
            # Format text "x% (y GB of z GB)"
            processed += "% (" + str(helper.format_bytes(data_size)) + " of "
            processed += str(helper.format_bytes(total_data_size)) + ")"
            progress["Processed data"] = processed
        # Avoid 0 division
        current = progress_state.get("BackendFileProgress", 0)
        total = progress_state.get("BackendFileSize", 0)
        if current > 0 and total > 0:
            backend_progress = "{0:.2f}".format(current / total * 100)
            progress["Backend"]["Progress"] = backend_progress + "%"
        # Don't show the backend stats on finished tasks
        phase = progress_state.get("Phase", "")
        if phase in ["Backup_Complete", "Error"]:
            progress.pop("Backend")

        backup["Schedule"] = schedule
        backup["Progress"] = progress
        key = {
            backup_name: backup
        }
        backup_list.append(key)

    return backup_list


# Dimiss notifications
def dismiss_notifications(data, resource_id="all"):
    common.verify_token(data)

    id_list = []
    if resource_id == "all":
        # Get all notification ID's
        notifications = fetch_resource_list(data, "notifications")
        for notification in notifications:
            id_list.append(notification["ID"])
    else:
        id_list.append(resource_id)

    if len(id_list) == 0:
        common.log_output("No notifications", True)
        return

    for item in id_list:
        delete_resource(data, "notification", item, True)


# Fetch logs
def get_logs(data, log_type, backup_id, remote=False,
             follow=False, lines=10, show_all=False):
        common.verify_token(data)

        if log_type == "backup" and backup_id is None:
            common.log_output("A backup id must be provided with --id", True)
            sys.exit(2)

        # Treating functions as objects to allow any function to be "followed"
        if log_type == "backup" and remote:
            def function():
                get_backup_logs(data, backup_id, "remotelog", lines, show_all)
        elif log_type == "backup" and not remote:
            def function():
                get_backup_logs(data, backup_id, "log", lines, show_all)
        elif log_type in ["profiling", "information", "warning", "error"]:
            def function():
                get_live_logs(data, log_type, lines)
        elif log_type == "stored":
            def function():
                get_stored_logs(data, lines, show_all)

        # Follow the function or just run it once
        if follow:
            follow_function(function, 10)
        else:
            function()


# Get local and remote backup logs
def get_backup_logs(data, backup_id, log_type, page_size=5, show_all=False):
    endpoint = "/api/v1/backup/" + str(backup_id) + "/" + log_type
    baseurl = common.create_baseurl(data, endpoint)
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    params = {'pagesize': page_size}

    r = requests.get(baseurl, headers=headers, cookies=cookies, params=params,
                     verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code == 500:
        message = "Error getting log, "
        message += "database may be locked by backup"
        common.log_output(message, True)
        return
    elif r.status_code != 200:
        common.log_output("Error getting log", True, r.status_code)
        return

    result = r.json()[-page_size:]
    logs = []
    for log in result:
        if log.get("Operation", "") == "list":
            log["Data"] = "Expunged"
        else:
            log["Data"] = json.loads(log.get("Data", "{}"))
            size = helper.format_bytes(log["Data"].get("Size", 0))
            log["Data"]["Size"] = size

        if log.get("Message", None) is not None:
            log["Message"] = log["Message"].split("\n")
            message_length = len(log["Message"])
            if message_length > 15 and not show_all:
                log["Message"] = log["Message"][:15]
                lines = str(message_length - 15)
                hidden_message = lines + " hidden lines (show with --all)"
                log["Message"].append(hidden_message)
        if log.get("Exception", None) is not None:
            log["Exception"] = log["Exception"].split("\n")
            exception_length = len(log["Exception"])
            if exception_length > 15 and not show_all:
                log["Exception"] = log["Exception"][:15]
                lines = str(exception_length - 15)
                hidden_message = lines + " hidden lines (show with --all)"
                log["Exception"].append(hidden_message)

        log["Timestamp"] = datetime.datetime.fromtimestamp(
            int(log.get("Timestamp", 0))
        ).strftime("%I:%M:%S %p %d/%m/%Y")
        logs.append(log)
    message = yaml.safe_dump(logs, default_flow_style=False)
    common.log_output(message, True)


# Get live logs
def get_live_logs(data, level, page_size=5, first_id=0):
    baseurl = common.create_baseurl(data, "/api/v1/logdata/poll")
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    params = {'level': level, 'id': first_id, 'pagesize': page_size}

    r = requests.get(baseurl, headers=headers, cookies=cookies, params=params,
                     verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code == 500:
        message = "Error getting log, "
        message += "database may be locked by backup"
        common.log_output(message, True)
        return
    elif r.status_code != 200:
        common.log_output("Error getting log", True, r.status_code)
        return

    result = r.json()[-page_size:]
    logs = []
    for log in result:
        log["When"] = helper.format_time(log.get("When", ""), True)
        logs.append(log)

    if len(logs) == 0:
        common.log_output("No log entries found", True)
        return

    message = yaml.safe_dump(logs, default_flow_style=False)
    common.log_output(message, True)


# Get stored logs
def get_stored_logs(data, page_size=5, show_all=False):
    baseurl = common.create_baseurl(data, "/api/v1/logdata/log")
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    params = {'pagesize': page_size}

    r = requests.get(baseurl, headers=headers, cookies=cookies, params=params,
                     verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code == 500:
        message = "Error getting log, "
        message += "database may be locked by backup"
        common.log_output(message, True)
        return
    elif r.status_code != 200:
        common.log_output("Error getting log", True, r.status_code)
        return

    result = r.json()[-page_size:]
    logs = []
    for log in result:
        if log.get("Message", None) is not None:
            log["Message"] = log["Message"].split("\n")
            message_length = len(log["Message"])
            if message_length > 15 and not show_all:
                log["Message"] = log["Message"][:15]
                lines = str(message_length - 15)
                hidden_message = lines + " hidden lines (show with --all)"
                log["Message"].append(hidden_message)
        if log.get("Exception", None) is not None:
            log["Exception"] = log["Exception"].split("\n")
            exception_length = len(log["Exception"])
            if exception_length > 15 and not show_all:
                log["Exception"] = log["Exception"][:15]
                lines = str(exception_length - 15)
                hidden_message = lines + " hidden lines (show with --all)"
                log["Exception"].append(hidden_message)
        logs.append(log)

    if len(logs) == 0:
        common.log_output("No log entries found", True)
        return

    message = yaml.safe_dump(logs, default_flow_style=False)
    common.log_output(message, True)


# Repeatedly call other functions until interrupted
def follow_function(function, interval=5):
    try:
        while True:
            compatibility.clear_prompt()
            function()
            timestamp = helper.format_time(datetime.datetime.now(), True)
            common.log_output(timestamp, True)
            common.log_output("Press control+C to quit", True)
            time.sleep(interval)
    except KeyboardInterrupt:
        return


# Call the API to schedule a backup run next
def run_backup(data, backup_id):
    common.verify_token(data)

    path = "/api/v1/backup/" + str(backup_id) + "/run"
    baseurl = common.create_baseurl(data, path)
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    r = requests.post(baseurl, headers=headers, cookies=cookies, verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code != 200:
        common.log_output("Error scheduling backup ", True, r.status_code)
        return
    common.log_output("Backup scheduled", True, 200)


# Call the API to abort a task
def abort_task(data, task_id):
    common.verify_token(data)

    path = "/api/v1/task/" + str(task_id) + "/abort"
    baseurl = common.create_baseurl(data, path)
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    r = requests.post(baseurl, headers=headers, cookies=cookies, verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code != 200:
        common.log_output("Error aborting task ", True, r.status_code)
        return
    common.log_output("Task aborted", True, 200)


# Delete wrapper
def delete_resource(data, resource_type, resource_id,
                    confirm=False, delete_db=False):
    if resource_type == "backup":
        delete_backup(data, resource_id, confirm, delete_db)
    elif resource_type == "notification":
        delete_notification(data, resource_id)


# Call the API to delete a backup
def delete_backup(data, backup_id, confirm=False, delete_db=False):
    common.verify_token(data)

    # Check if the backup exists
    result = fetch_backups(data, [backup_id], "get")
    if result is None or len(result) == 0:
        return

    if not confirm:
        # Confirm deletion with user
        name = next(iter(result[0]))
        message = 'Delete "' + name + '"? (ID:' + str(backup_id) + ')'
        options = '[y/N]:'
        agree = input(message + ' ' + options)
        if agree not in ["Y", "y", "yes", "YES"]:
            common.log_output("Backup not deleted", True)
            return

    baseurl = common.create_baseurl(data, "/api/v1/backup/" + str(backup_id))
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    # We cannot delete remote files because the captcha is graphical
    payload = {'delete-local-db': delete_db, 'delete-remote-files': False}

    r = requests.delete(baseurl, headers=headers, cookies=cookies,
                        params=payload, verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code != 200:
        common.log_output("Error deleting backup", True, r.status_code)
        return
    common.log_output("Backup deleted", True, 200)


# Call the API to delete a notification
def delete_notification(data, notification_id):
    common.verify_token(data)

    url = "/api/v1/notification/"
    baseurl = common.create_baseurl(data, url + str(notification_id))
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    r = requests.delete(baseurl, headers=headers, cookies=cookies,
                        verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code == 404:
        common.log_output("Notification not found", True, r.status_code)
        return
    elif r.status_code != 200:
        common.log_output("Error deleting notification", True, r.status_code)
        return
    common.log_output("Notification deleted", True, 200)


def update_backup(data, backup_id, backup_config, import_meta=True):
    common.verify_token(data)

    # Strip metadata if requested
    if import_meta is not None and not import_meta:
        backup_config.get("Backup", {}).pop("Metadata", None)

    baseurl = common.create_baseurl(data, "/api/v1/backup/" + str(backup_id))
    cookies = common.create_cookies(data)
    headers = common.create_headers(data)
    verify = data.get("server", {}).get("verify", True)
    payload = json.dumps(backup_config, default=str)
    r = requests.put(baseurl, headers=headers, cookies=cookies,
                     data=payload, verify=verify)
    common.check_response(data, r.status_code)
    if r.status_code == 404:
        common.log_output("Backup not found", True, r.status_code)
        return
    elif r.status_code != 200:
        common.log_output("Error updating backup", True, r.status_code)
        return
    common.log_output("Backup updated", True, 200)


# Toggle verbosity
def toggle_verbose(data, mode=None):
    if mode == "enable":
        data["verbose"] = True
    elif mode == "disable":
        data["verbose"] = False
    else:
        data["verbose"] = not data.get("verbose", False)

    common.write_config(data)
    verbose = data.get("verbose", True)
    message = "verbose mode: " + str(verbose)
    common.log_output(message, True)
    return data


# Print the status to stdout
def display_status(data):
    message = "Application version: " + config.APPLICATION_VERSION
    common.log_output(message, True)

    message = "Config file: " + config.CONFIG_FILE
    common.log_output(message, True)

    if data.get("parameters_file", None) is not None:
        param_file = data.get("parameters_file", "")
        message = "Params file: " + param_file
        common.log_output(message, True)

    token = data.get("token", None)
    token_expires = data.get("token_expires", None)
    if token is None or token_expires is None:
        common.log_output("Not logged in", True)
        sys.exit(2)

    if data.get("last_login", None) is not None:
        last_login = data.get("last_login", "")
        message = "Logged in  : " + helper.format_time(last_login)
        common.log_output(message, True)

    if token_expires is not None:
        message = "Expiration : " + helper.format_time(token_expires)
        common.log_output(message, True)


# Load the configration from disk
def load_config(data, overwrite=False):
    # If the config file doesn't exist, create it
    if os.path.isfile(config.CONFIG_FILE) is False or overwrite is True:
        common.log_output("Creating config file", True)
        common.write_config(data)
    # Load the configuration from the config file
    with open(config.CONFIG_FILE, 'r') as file:
        try:
            data = yaml.safe_load(file)
            common.validate_config(data)
            return data
        except yaml.YAMLError as exc:
            common.log_output(exc, True)
            sys.exit(2)


# Print the config to stdout
def display_config(data):
    common.log_output(yaml.dump(data, default_flow_style=False), True)


# Set parameters file
def set_parameters_file(data, args, file=None):
    # Disable parameters file if requested
    if args.get("disable", False):
        data.pop("parameters_file", None)
        common.write_config(data)
        common.log_output("Disabling parameters-file", True)
        return data

    if file is None:
        return data

    data["parameters_file"] = file
    common.write_config(data)
    common.log_output("Setting parameters-file", True)
    return data


# Print parameters to stdout
def display_parameters(data):
    file = data.get("parameters_file", None)
    if file is None:
        return
    with open(file, 'r') as file_handle:
        try:
            parameters_file = yaml.safe_load(file_handle)
            output = yaml.dump(parameters_file, default_flow_style=False)
            common.log_output(output, True)
            return
        except Exception:
            message = "Could not load parameters file"
            common.log_output(message, True)
            return


# Import resource wrapper function
def import_resource(data, resource, import_file, backup_id, import_meta=None):
    if resource == "backup":
        import_backup(data, import_file, backup_id, import_meta)


# Import backup configuration from a YAML or JSON file
def import_backup(data, import_file, backup_id=None, import_meta=None):
    # Don't load nonexisting files
    if os.path.isfile(import_file) is False:
        common.log_output(import_file + " not found", True)
        return

    # Load the import file
    with open(import_file, 'r') as file_handle:
        extension = splitext(import_file)[1]
        if extension.lower() in ['.yml', '.yaml']:
            try:
                backup_config = yaml.safe_load(file_handle)
            except yaml.YAMLError:
                common.log_output("Failed to load file as YAML", True)
                return

        elif extension.lower() == ".json":
            try:
                backup_config = json.load(file_handle)
            except Exception:
                common.log_output("Failed to load file as JSON", True)
                return

    # Determine if we're importing a new backup or updating an existing backup
    if backup_id is not None:
        return update_backup(data, backup_id, backup_config, import_meta)

    common.verify_token(data)

    # Strip metadata if requsted
    if import_meta is None or import_meta is not True:
        backup_config["Backup"]["Metadata"] = {}

    # Prepare the imported JSON object as a string
    backup_config = json.dumps(backup_config, default=str)

    # Upload our JSON string as a file with requests
    files = {
        'config': ('backup_config.json', backup_config, 'application/json')
    }

    # Will eventually support passphrase encrypted configs, but we will
    # need to decrypt them in the client in order to convert them
    payload = {
        'passphrase': '',
        'import_metadata': import_meta,
        'direct': True
    }
    cookies = common.create_cookies(data)
    baseurl = common.create_baseurl(data, "/api/v1/backups/import", True)
    verify = data.get("server", {}).get("verify", True)
    r = requests.post(baseurl, files=files, cookies=cookies, data=payload,
                      verify=verify)
    common.check_response(data, r.status_code)
    # Code for extracting error messages posted with inline javascript
    # and with 200 OK http status code, preventing us from detecting
    # the error otherwise.
    try:
        text = r.text
        start = text.index("if (rp) { rp('")+14
        end = text.index(", line ")
        error = text[start:end].replace("\\'", "'") + "."
        common.log_output(error, True)
        sys.exit(2)
    except ValueError:
        pass
    if r.status_code != 200:
        message = "Error importing backup configuration"
        common.log_output(message, True, r.status_code)
        sys.exit(2)
    common.log_output("Backup job created", True, 200)


# Export resource wrapper function
def export_resource(data, resource, resource_id, output=None, path=None):
    if resource == "backup":
        export_backup(data, resource_id, output, path)


# Export backup configuration to either YAML or JSON file
def export_backup(data, backup_id, output=None, path=None):
    # Get backup config
    result = fetch_backups(data, [backup_id], "describe")
    if result is None or len(result) == 0:
        common.log_output("Could not fetch backup", True)
        return
    backup = result[0]
    # Strip DisplayNames and Progress
    # backup.pop("DisplayNames", None)
    backup.pop("Progress", None)

    # Fetch server version
    systeminfo = fetch_resource_list(data, "systeminfo")

    if systeminfo.get("ServerVersion", None) is None:
        common.log_output("Error exporting backup", True)
        sys.exit(2)

    backup["CreatedByVersion"] = systeminfo["ServerVersion"]

    # YAML or JSON?
    if output in ["JSON", "json"]:
        filetype = ".json"
    else:
        filetype = ".yml"

    # Decide on where to output file
    if path is None:
        time = datetime.datetime.now().strftime("%d.%m.%Y_%I.%M_%p")
        path = "backup_config_" + str(time) + filetype
    else:
        path = expanduser(path)

    # Check if output folder exists
    directory = os.path.dirname(path)
    if directory != '' and not os.path.exists(directory):
        message = "Created directory \"" + directory + "\""
        common.log_output(message, True)
        os.makedirs(directory)
    # Check if output file exists
    if os.path.isfile(path) is True:
        agree = input('File already exists, overwrite? [Y/n]:')
        if agree not in ["Y", "y", "yes", "YES", ""]:
            return
    with open(path, 'w') as file:
        if filetype == ".json":
            file.write(json.dumps(backup, indent=4, default=str))
        else:
            file.write(yaml.dump(backup, default_flow_style=False))
    common.log_output("Created " + path, True, 200)


# argparse argument logic
if __name__ == '__main__':
    if (len(sys.argv) == 1):
        common.log_output(common.info(), True)
        sys.exit(2)

    # Initialize argument parser and standard optional arguments
    parser = ArgumentParser.parser

    # Construct parsers and initialize the main method
    args = parser.parse_args()
    main(**vars(args))
