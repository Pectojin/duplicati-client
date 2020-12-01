# Module for small helper functions that are mostly generic
import common
import datetime

from dateutil import parser as dateparser
from dateutil import tz


# Helper function for formatting timestamps for humans
def format_time(data, time_string):
    precise = data.get("precise", False)
    # Ensure it's a string
    time_string = str(time_string)

    # Filter out "unset" time
    if time_string == "0001-01-01T00:00:00Z" or time_string == "0":
        return None

    # We want to fail silently if we're not provided a parsable time_string.
    try:
        datetime_object = dateparser.parse(time_string)
    except Exception as exc:
        common.log_output(exc, False)
        return None

    # Print a precise, but human readable string if precise is true
    if precise:
        return datetime_object.strftime("%I:%M:%S %p %d/%m/%Y")

    # Now for comparison
    now = datetime.datetime.now().replace(tzinfo=tz.tzutc())
    datetime_object = datetime_object.replace(tzinfo=tz.tzutc())

    # Get the delta
    if datetime_object > now:
        delta = (datetime_object - now)
    else:
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


# Helper function for formatting time deltas for humans
def format_duration(duration_string):
    duration = duration_string.split(".")[0]
    return duration


# Helper function for human readable bit sizes
# Source https://stackoverflow.com/questions/12523586/
def format_bytes(number_of_bytes):
    if number_of_bytes < 0:
        raise ValueError("!!! numberOfBytes can't be smaller than 0 !!!")

    step_to_greater_unit = 1024.

    number_of_bytes = float(number_of_bytes)
    unit = 'bytes'

    if (number_of_bytes / step_to_greater_unit) >= 1:
        number_of_bytes /= step_to_greater_unit
        unit = 'KB'

    if (number_of_bytes / step_to_greater_unit) >= 1:
        number_of_bytes /= step_to_greater_unit
        unit = 'MB'

    if (number_of_bytes / step_to_greater_unit) >= 1:
        number_of_bytes /= step_to_greater_unit
        unit = 'GB'

    if (number_of_bytes / step_to_greater_unit) >= 1:
        number_of_bytes /= step_to_greater_unit
        unit = 'TB'

    precision = 2
    number_of_bytes = round(number_of_bytes, precision)

    return str(number_of_bytes) + ' ' + unit
