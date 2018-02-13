#!/usr/bin/env python3
import argparse as ap, sys, os.path
from os.path import expanduser
import requests
import urllib
import yaml, json
import getpass
import hashlib, base64
import datetime
from dateutil import tz, parser as dateparser

# Global values
config_file = "config.yml"
verbose = True

def main(**args):
	# Command method
	method = sys.argv[1]

	# Default values
	global verbose
	global config_file
	# Detect home dir for config file
	home = expanduser("~")
	config_file = home + "/.config/duplicati_client/config.yml"
	data = {
		"last_login": None,
		"parameters_file": None,
		"server": {
			"port": "8200",
			"protocol": "http",
			"url": "localhost",
		},
		'token': None,
		'verbose': True
	}

	# Use an alternative config file if --config-file is provided
	if args.get("config_file", False):
		config_file = args["config_file"]

	# Load configuration
	data = load_config(data)

	# Set parameters file
	if method == "params":
		data = set_parameters_file(data, args, args.get("param-file", None))

	# Load parameters file
	load_parameters(data, args)

	# Toggle verbosity
	if method == "verbose":
		toggle_verbose(data)

	# Write verbosity setting to global variable
	verbose = data.get("verbose", False)

	# Display the config if requested
	if method == "config":
		display_config(data)

	# Display the status if requested
	if method == "status":
		display_status(data)

	# Login
	if method == "login":
		data = login(data, args.get("url", None), args.get("password", None))

	# Logout
	if method == "logout":
		data = logout(data)

	# List resources
	if method == "list":
		list_resources(data, args["type"])

	# Get resources
	if method == "get":
		get_resources(data, args["type"], args["id"])

	# Get resources
	if method == "describe":
		describe_resource(data, args["type"], args["id"])

	# Show logs

	# Run backup
	if method == "run":
  		run_backup(data, args["id"])

	# Abort backup
	if method == "abort":
		abort_task(data, args["id"])

	# Import method
	if method == "import":
		return
		#import_backup(data, args["type"], args[""])

	# Export method
	if method == "export":
		export_resource(data, args["type"], args["id"], args.get("output", None), args.get("output_path", None))

def list_resources(data, resource):
	if data.get("token", None) is None:
		log_output("Not logged in", True)
		return
	baseurl = create_baseurl(data, "/api/v1/")
	log_output("Fetching list from API...", False)
	cookies = create_cookies(data)
	headers = create_headers(data)
	r = requests.get(baseurl + resource, headers=headers, cookies=cookies)
	if r.status_code == 400:
		log_output("Session expired. Please login again", True, r.status_code)
		return
	elif r.status_code != 200:
		log_output("Error connecting", True, r.status_code)
		return
	resource_list = list_filter(r.json(), resource)
	# Must use safe_dump for python 2 compatibility
	log_output(yaml.safe_dump(resource_list, default_flow_style=False), True)

# Filter logic for the list function to facilitate readable output
def list_filter(json_input, resource):
	resource_list = []
	if resource == "backups":
		for key in json_input:
			backup = key["Backup"]
			schedule = key["Schedule"]
			backup_name = backup.get("Name", "")
			backup = {
				backup_name: {
					"ID": backup.get("ID", ""),
				}
			}

			if backup.get('Metadata', {}).get('SourceSizeString') is not None:
				backup[backup_name]["Source size"] = backup.get('Metadata', {}).get('SourceSizeString'),
			if schedule is not None:
				next_run = format_time(schedule.get("Time", ""))
				if next_run is not None:
					backup[backup_name]["Next run"] = next_run
				last_run = format_time(schedule.get("LastRun", ""))
				if last_run is not None:
					backup[backup_name]["Last run"] = last_run
			resource_list.append(backup)
	elif resource == "notifications":
		for val in json_input:
			notification = {
				val.get("Title", ""): {
					"Backup ID": val.get("BackupID", ""),
					"Notification ID": val.get("ID", ""),
				}
			}
			timestamp = format_time(val.get("Timestamp", ""))
			if timestamp is not None:
				notification["Timestamp"] = timestamp

			resource_list.append(notification)
	elif resource == "serversettings":
		for key, value in json_input.items():
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
def get_resources(data, resource, backup_ids):
	if resource == "backup":
		fetch_backup(data, resource, backup_ids, "get")
	elif resource == "notification":
		fetch_notification(data, resource, notification_ids, "get")

# Get one resource with all fields
def describe_resource(data, resource, backup_id):
	result = fetch_backup(data, resource, [backup_id], "describe")
	# Must use safe_dump for python 2 compatibility
	log_output(yaml.safe_dump(result, default_flow_style=False), True)


# Fetch resources
def fetch_backup(data, resource, backup_ids, method):
	if data.get("token", None) is None:
		log_output("Not logged in", True)
		return

	baseurl = create_baseurl(data, "/api/v1/")
	log_output("Fetching list from API...", False)
	cookies = create_cookies(data)
	headers = create_headers(data)
	resource_list = []
	# Check progress state and get info for the running backup if any is running
	r = requests.get(baseurl + "progressstate", headers=headers, cookies=cookies)
	if r.status_code != 200:
		log_output("Error getting progressstate ", False, r.status_code)
		active_id = None
	else:
		progress_state = r.json()
		active_id = progress_state.get("BackupID", -1)
	# Iterate over backup_ids and fetch their info
	for backup_id in backup_ids:
		r = requests.get(baseurl + resource + "/" + backup_id, headers=headers, cookies=cookies)
		if r.status_code == 400:
			log_output("Session expired. Please login again", True, r.status_code)
			return
		if r.status_code != 200:
			log_output("Error getting backup " + backup_id, True, r.status_code)
			continue
		data = r.json()["data"]
		if active_id is not None and data.get("Backup", {}).get("ID", 0) == active_id:
			data["Progress"] = progress_state
		resource_list.append(data)

	# Only get uses a filter
	if method == "get":
		resource_list = get_filter(resource_list, resource)

	return resource_list

# Filter logic for the get function to facilitate readable output
def get_filter(json_input, resource):
	resource_list = []
	if resource == "backup":
		for key in json_input:
			backup = key["Backup"]
			backup.pop("DBPath", None)
			backup.pop("IsTemporary", None)
			backup.pop("Metadata", None)
			backup.pop("Filters", None)
			backup.pop("TargetURL", None)
			backup.pop("Tags", None)
			backup.pop("Sources", None)
			backup.pop("Settings", None)

			schedule = key.get("Schedule", None)
			if schedule is not None:
				next_run = format_time(schedule.pop("Time", ""))
				if next_run is not None:
					schedule["Next run"] = next_run
				last_run = format_time(schedule.pop("LastRun", ""))
				if last_run is not None:
					schedule["Last run"] = last_run
				schedule.pop("AllowedDays", None)
				schedule.pop("ID", None)
				schedule.pop("Rule", None)
				schedule.pop("Tags", None)

			progress_state = key.get("Progress", {})
			progress = {
				"State": progress_state.get("Phase", None),
				"Counting": progress_state.get("StillCounting", False),
				"Backend": {
					"BackendAction": progress_state.get("BackendAction", 0),
				},
				"Task ID": progress_state.get("TaskID", -1)
			}
			# Display item only if relevant
			if not progress_state.get("StillCounting", False):
				progress.pop("Counting")
			# Avoid 0 division
			if progress_state.get("ProcessedFileCount", 0) > 0 and progress_state.get("TotalFileCount", 0) > 0:
				progress["Backend"]["Processed files"] = str(progress_state.get("ProcessedFileCount", 1) / progress_state.get("TotalFileCount", 1) * 100) + "%"
			# Avoid 0 division
			if progress_state.get("BackendFileProgress", 0) > 0 and progress_state.get("BackendFileSize", 0) > 0:
				progress["Backend"]["BackendProgress"] = str(progress_state["BackendFileProgress"] / progress_state["BackendFileSize"] * 100) + "%",
			# Don't show the backend stats on finished tasks
			if progress_state.get("Phase", "") == "Backup_Complete":
				progress.pop("Backend")

			key["Backup"] = backup
			key["Schedule"] = schedule
			key["Progress"] = progress
			key.pop("DisplayNames", None)
			resource_list.append(key)

	return resource_list

# Call the API to schedule a backup run next
def run_backup(data, backup_id):
	if data.get("token", None) is None:
		log_output("Not logged in", True)
		return

	baseurl = create_baseurl(data, "/api/v1/")
	log_output("Fetching list from API...", False)
	cookies = create_cookies(data)
	headers = create_headers(data)
	# Check progress state and get info for the running backup if any is running
	r = requests.post(baseurl + "backup/" + str(backup_id) + "/run", headers=headers, cookies=cookies)
	if r.status_code == 400:
		log_output("Session expired. Please login again", True, r.status_code)
		return
	elif r.status_code != 200:
		log_output("Error scheduling backup ", True, r.status_code)
		return
	log_output("Backup scheduled", True)

# Call the API to abort a task
def abort_task(data, task_id):
	if data.get("token", None) is None:
		log_output("Not logged in", True)
		return

	baseurl = create_baseurl(data, "/api/v1/")
	log_output("Fetching list from API...", False)
	cookies = create_cookies(data)
	headers = create_headers(data)
	# Check progress state and get info for the running backup if any is running
	r = requests.post(baseurl + "task/" + str(task_id) + "/abort", headers=headers, cookies=cookies)
	if r.status_code == 400:
		log_output("Session expired. Please login again", True, r.status_code)
		return
	elif r.status_code != 200:
		log_output("Error aborting task ", True, r.status_code)
		return
	log_output("Task aborted", True)

# Login by authenticating against the Duplicati API and extracting a token
def login(data, input_url=None, password=None):
	# Split protocol, url, and port if port is provided as CLI argument
	if input_url is not None:
		# fallback values loaded from config file ("defaults")
		protocol = data["server"]["protocol"]
		url = data["server"]["url"]
		port = data["server"]["port"]
		# Begin parsing the input url
		input_url = input_url.replace("//", "")
		count = input_url.count(":")
		if count == 2:
			protocol, url, port = input_url.split(":")
		elif count == 1 and input_url.index(":") < 6:
			protocol, url = input_url.split(":")
		elif count == 1:
			url, port = input_url.split(":")
		else:
			url = input_url

	# Update config
	data["server"]["protocol"] = protocol
	data["server"]["url"] = url
	data["server"]["port"] = port
	# Make the login attempt
	baseurl = create_baseurl(data, "")
	log_output("Connecting to " + baseurl + "...", False)
	r = requests.get(baseurl, allow_redirects=False)
	if r.status_code == 200:
		log_output("OK", False, r.status_code)
		token = unquote(r.cookies["xsrf-token"])
	elif r.status_code == 302:
		# Get password by prompting user if no password was given in-line
		if password is None:
			log_output("Authentication required", True, r.status_code)
			password = getpass.getpass('Password:')
		
		log_output("Getting nonce and salt...", False)
		payload = { 'get-nonce': 1 }
		r = requests.post(baseurl + "/login.cgi", data=payload)
		if r.status_code != 200:
			log_output("Error getting salt from server", True, r.status_code)
			return

		salt = r.json()["Salt"]
		data["nonce"] = r.json()["Nonce"]
		token = unquote(r.cookies["xsrf-token"])
		log_output("Hashing password...", False)
		saltedpwd = hashlib.sha256(password.encode() + base64.b64decode(salt)).digest()
		noncedpwd = hashlib.sha256(base64.b64decode(data["nonce"]) + saltedpwd).digest()

		log_output("Authenticating... ", False)
		payload = { "password": base64.b64encode(noncedpwd).decode('utf-8') }
		cookies = { "xsrf-token": token, "session-nonce": data.get("nonce", "") }
		r = requests.post(baseurl + "/login.cgi", data=payload, cookies=cookies)
		if r.status_code == 200:
			log_output("Connected", True, r.status_code)
			data["session-auth"] = unquote(r.cookies["session-auth"])
		else:
			log_output("Error authenticating against the server", True, r.status_code)
	else:
		log_output("Error connecting to server", True, r.status_code)
		return

	# Update the config file with provided values
	data["token"] = token
	data["last_login"] = datetime.datetime.now()
	write_config(data)
	return

# Logout by deleting the token from memory and disk
def logout(data):
	log_output("Logging out...", True)
	data["token"] = None
	write_config(data)
	return data

# Logging function
def log_output(text, important, code=None):
	global verbose
	if verbose is False and important is False:
		return
	if code is None:
		print(text)
		return

	print(text + ", code: " + str(code))

# Common function for creating cookies to authenticate against the API
def create_cookies(data):
	# return { "xsrf-token": data.get("token", "") }
	if data.get("nonce", None) is None:
		return { "xsrf-token": data.get("token", "") }
	else:
		return { "xsrf-token": data.get("token", ""), "session-nonce": data.get("nonce", ""), "session-auth": data.get("session-auth", "") }

# Common function for creating headers to authenticate against the API
def create_headers(data):
	return { "X-XSRF-TOKEN": data.get("token", "") }

# Common function for creating a base url
def create_baseurl(data, additional_path):
	protocol = data["server"]["protocol"]
	url = data["server"]["url"]
	port = data["server"]["port"]
	return protocol + "://" + url + ":" + port + additional_path

# Load the configration from disk - Falls back to creating a default config if none exists
def load_config(data):
	global config_file
	# If the config file doesn't exist, create it
	if os.path.isfile(config_file) is False:
		log_output("Creating config file", True)
		write_config(data)
	# Load the configuration from the config file
	with open(config_file, 'r') as file:
	    try:
	        data = yaml.safe_load(file)
	        return data
	    except yaml.YAMLError as exc:
	        log_output(exc, True)

def format_time(timestring):
	# Filter out "unset" time
	if timestring == "0001-01-01T00:00:00Z":
		return None

	# We want to fail silently if we're not provided a parsable timestring.
	try:
		datetime_object = dateparser.parse(timestring)
	except Exception as exc:
		log_output(exc, False)
		return None

	# Now for comparison
	now = datetime.datetime.now()

	# Take care of timezones
	now = now.replace(tzinfo=tz.tzutc()).astimezone(tz.tzlocal())
	datetime_object = datetime_object.replace(tzinfo=tz.tzutc()).astimezone(tz.tzlocal())

	# Get the delta
	delta = (now - datetime_object)
	# Display hours if within 24 hours of now, else display dmy
	if abs(delta.days) > 1:
		return datetime_object.strftime("%d/%m/%Y")
	elif delta.days == 1:
		return "Yesterday " + datetime_object.strftime("%I:%M %p")
	elif delta.days == -1:
		return "Tomorrow " + datetime_object.strftime("%I:%M %p")
	else:
		return datetime_object.strftime("%I:%M %p")

# Print the status to stdout
def display_status(data):
	if data.get("token", None) is not None:
		log_output("Logged in", True)
	else:
		log_output("Not logged in", True)
	if data.get("last_login", None) is not None:
		log_output("Last login: " + str(data["last_login"]), True)
	if data.get("parameters_file", None) is not None:
		log_output("Parameters file: " + data["parameters_file"], True)

# Toggle verbosity
def toggle_verbose(data):
	data["verbose"] = not data.get("verbose", False)
	write_config(data)
	log_output("verbose mode: " + str(data["verbose"]), True)

# Set parameters file
def set_parameters_file(data, args, file=None):
	if file is None:
		return

	# Disable parameters file if requests
	if args.get("disable", False):
		data.pop("parameters_file", None)
		write_config(data)
		log_output("Disabling parameters-file", True)
		return data

	data["parameters_file"] = file
	write_config(data)
	log_output("Setting parameters-file", True)
	return data

# Load parameters from file
def load_parameters(data, args):
	# Check for parameters file
	file = data.get("parameters_file", None)
	if file is None:
		return args

	# Don't load nonexisting files
	if os.path.isfile(file) is False:
		return args

	# Load the parameters from the file
	with open(file, 'r') as file_handle:
	    try:
	        parameters_file = yaml.safe_load(file_handle)
	        log_output("Loaded " + str(len(parameters_file)) + " parameters from file", True)
        	# any arg can be inserted, so currently I see no point in validating what goes in.
        	for key, value in parameters_file.items():
        		# Just make sure not to override CLI provided arguments
        		if args.get(key, None) is None:
        			args[key] = value
        	
        	# Have to manually handle this special case because verbose is a command not an argument
        	if parameters_file.get("verbose", None) is not None:
        		data["verbose"] = parameters_file.get("verbose")

        	# Update parameters_file variable in config file
        	data["parameters_file"] = file
        	write_config(data)
        	return args
	    except yaml.YAMLError as exc:
	        log_output(exc, True)
	        return args

# Export resource wrapper function
def export_resource(data, resource, resource_id, output=None, output_path=None):
	if resource == "backup":
		export_backup(data, resource_id, output, output_path)

# Export backup configuration to either YAML or JSON file
def export_backup(data, backup_id, output=None, output_path=None):
	# Get backup config
	result = fetch_backup(data, "backup", [backup_id], "describe")
	if result is None or len(result) == 0:
		log_output("Could not fetch backup", True)
		return
	backup = result[0]
	# Strip DisplayNames and Progress
	backup.pop("DisplayNames", None)
	backup.pop("Progress", None)

	# YAML or JSON?
	if output in ["JSON", "json"]:
		filetype = ".json"
	else:
		filetype = ".yml"
	
	# Decide on where to output file
	if output_path is None:
		output_path = "backup_config" + str(datetime.datetime.now()) + filetype
	else:
		output_path = expanduser(output_path)

	# Check if output folder exists
	directory = os.path.dirname(output_path)
	if directory != '' and not os.path.exists(directory):
		log_output("Created directory \"" + directory + "\"", True)
		os.makedirs(directory)
	# Check if output file exists
	if os.path.isfile(output_path) is True:
		agree = input('File already exists, overwrite? [Y/n]:')
		if agree not in ["Y", "y", "yes", "YES", ""]:
			return
	with open(output_path, 'w') as file:
		if filetype == ".json":
			file.write(json.dumps(backup, indent=4, default=str))
		else:
			file.write(yaml.dump(backup, default_flow_style=False))
	return

# Print the config to stdout
def display_config(data):
	log_output(yaml.dump(data, default_flow_style=False), True)

# Write config to file
def write_config(data):
	global config_file
	directory = os.path.dirname(config_file)
	if not os.path.exists(directory):
		log_output("Created directory \"" + directory + "\"", True)
		os.makedirs(directory)
	with open(config_file, 'w') as file:
		file.write(yaml.dump(data, default_flow_style=False))

# Client intro
def info():
	return """Duplicati Client

This client connects to Duplicati servers remotely or locally and helps manage them easily through the commandline.
A client daemon and cron mode is also available, allowing to periodically pull instructions from a central management server.

To begin log into a server:
    duplicati login https://my.duplicati.server

or see --help to see information on usage
"""

# Python 3 vs 2 urllib compatability issues
def unquote(text):
	if sys.version_info[0] >= 3:
		return urllib.parse.unquote(text)
	else:
		return urllib.unquote(text)

# argparse argument logic
if __name__ == '__main__':
	if (len(sys.argv) == 1):
		log_output(info(), True)
		sys.exit(2)
	# Initialize argument parser and standard optional arguments
	parser = ap.ArgumentParser()
	
	# Create subparsers
	subparsers = parser.add_subparsers(title='commands', metavar="<>", help="")
	# Subparser for the List method
	list_parser = subparsers.add_parser('list', help="List all resources of a given type")
	list_parser.add_argument('type', choices=["backups", "restores", "notifications", "serversettings"], help="the type of resource")
	# Subparser for the Get method
	get_parser = subparsers.add_parser('get', help="display breif information on one or many resources")
	get_parser.add_argument('type', choices=["backup"], help="the type of resource")
	get_parser.add_argument('id', nargs='+', help="one or more ID's to look up")
	# Subparser for the Describe method
	describe_parser = subparsers.add_parser('describe', help="display detailed information on a specific resource")
	describe_parser.add_argument('type', choices=["backup"], help="the type of resource")
	describe_parser.add_argument('id', help="the ID of the resource to look up")
	# Subparser for the Run method
	run_parser = subparsers.add_parser('run', help="run a backup job")
	run_parser.add_argument('id', help="the ID of the backup job to run")
	# Subparser for the Abort method
	abort_parser = subparsers.add_parser('abort', help="abort a task")
	abort_parser.add_argument('id', help="the ID of the task to abort")
	# Subparser for the Edit method
	edit_parser = subparsers.add_parser('edit', help="edit a resource on the server")
	edit_parser.add_argument('type', help="the type of resource")
	edit_parser.add_argument('id', help="the ID of the resource to edit")
	# Subparser for the Export method
	export_parser = subparsers.add_parser('export', help="export a resource from the server to YAMl or JSON format")
	export_parser.add_argument('type', choices=["backup"], help="the type of resource")
	export_parser.add_argument('id', help="the ID of the resource to export")
	export_parser.add_argument('--output', choices=["YAML", "JSON", "yaml", "json"], metavar='', help="output YAML or JSON, defaults to YAML")
	export_parser.add_argument('--output-path', metavar='', help="Path to output the file at")
	# Subparser for the Import method
	import_parser = subparsers.add_parser('import', help="import a resource from the server in YAMl or JSON format")
	import_parser.add_argument('type', choices=["backup"], help="the type of resource")
	import_parser.add_argument('import-file', nargs='?', help="file containing a job configuration in YAML or JSON format")
	import_parser.add_argument('--id', metavar='', help="Provide an ID to update an existing backup configuration")
	# Subparser for the Logs method
	logs_parser = subparsers.add_parser('logs', help="display the logs for a given job")
	logs_parser.add_argument('type', choices=["backup", "restore", "general", "live"],help="the type of resource")
	logs_parser.add_argument('id', nargs='?', help="If applicable")
	# Subparser for the Login method
	login_parser = subparsers.add_parser('login', help="log into a Duplicati server")
	login_parser.add_argument('url')
	login_parser.add_argument('--password', metavar='', help="password, will prompt if not provided")
	login_parser.add_argument('--insecure', action='store_true', help="allow insecure HTTPS connections to the server")
	login_parser.add_argument('--certfile', metavar='', help="specify the path to a cert file used to validate the certificate authority")
	login_parser.add_argument('--config-file', action='store', help="specify a non-standard configuration file", metavar='')
	# Subparser for the Logout method
	subparsers.add_parser('logout', help="end the current server session")
	# Subparser for the Status method
	subparsers.add_parser('status', help="return information about the current session")
	# Subparser for the Config method
	subparsers.add_parser('config', help="prints the config to stdout")
	# Subparser for the Daemon mode
	subparsers.add_parser('daemon', help="run Duplicati Client as a service")
	# Subparser for toggling verbose mode
	subparsers.add_parser('verbose', help="Toggle verbose mode")
	# Subparser for setting a parameter file
	parameters_file_parser = subparsers.add_parser('params', help="import parameters from a YAML file")
	parameters_file_parser.add_argument('param-file', nargs='?', help="path to file containing parameters in YAML format")
	parameters_file_parser.add_argument('--disable', action='store_true', help="disable the parameters file")
	# Construct parsers and initialize the main method
	args = parser.parse_args()
	main(**vars(args))
