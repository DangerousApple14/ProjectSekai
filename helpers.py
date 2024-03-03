import datetime as dt
import secrets
from email.message import EmailMessage
import ssl
import smtplib
import hashlib
import pytz

from keys import EMAIL_PASSWORD
from flask import redirect, render_template, session
from functools import wraps


class Reminder:    # create a 'Reminder' object that has both the reminder datetime and its task number
    def __init__(self, reminder, task_n):
        self.reminder = reminder
        self.task_n = task_n


def generate_token(n=16):
    return secrets.token_hex(n)  # Generate a hex token of (default) 16 bytes


def send_mail(obj, body, recipient, sender="st4rlight069@gmail.com"):   # Send email function
    em = EmailMessage()

    # Modify the em object's keys
    em['From'] = sender
    em['To'] = recipient
    em['Subject'] = obj
    em.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
        smtp.login(sender, EMAIL_PASSWORD)
        smtp.sendmail(sender, recipient, em.as_string())


def escape(s):
    """
    Escape special characters.

    https://github.com/jacebrowning/memegen#special-characters
    """
    for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                     ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
        s = s.replace(old, new)
    return s


def error(msg, code=400):   # return a meme with error message and code
    return render_template("error.html", img=f"https://api.memegen.link/images/ugandanknuck/{escape(msg)}/{code}_.png")


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def merge_date_time(date_str, time_str):
    # Convert the strings to date and time objects
    date_obj = dt.datetime.strptime(date_str, '%Y-%m-%d').date()
    time_obj = dt.datetime.strptime(time_str, '%H:%M').time()

    # Combine the date and time objects into a datetime object
    datetime_obj = dt.datetime.combine(date_obj, time_obj)

    return datetime_obj


def remove_t(datetime_obj):     # needed for '/set_reminders' route, since it saves datetime strings in format 'yyyy-mm-ddThh-mm-ss'. I asked ChatGPT for this
    """
    Remove 'T' from the datetime object and return a string representation.

    Args:
        datetime_obj: Datetime object or string representation of datetime.

    Returns:
        str: String representation of the datetime object.
    """
    if isinstance(datetime_obj, str):
        return datetime_obj.replace('T', ' ')
    elif isinstance(datetime_obj, dt.datetime):
        return datetime_obj.strftime("%Y-%m-%d %H:%M:%S")
    else:
        raise ValueError("Invalid input type. Expected datetime object or string representation of datetime.")


def parse_datetime(datetime_str):   # 'easier strptime' since it handles both datetime strings with and without seconds
    ZaWarudo = None
    try:
        ZaWarudo = dt.datetime.strptime(datetime_str, "%Y-%m-%d %H:%M")
    except ValueError:
        try:
            ZaWarudo = dt.datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return ZaWarudo


def generate_token_by_rn():     # Asked ChatGPT for this algorithm
    """Generate a cryptic token based on the current date and time."""
    current_time = dt.datetime.utcnow()
    token = hashlib.sha256(str(current_time).encode()).hexdigest()
    return token, current_time


def is_within_six_hours(time1, time2_str):     # check if 2 datetimes have 6 hours or less difference (return True or False accordingly)
    time2 = dt.datetime.strptime(time2_str, "%Y-%m-%d %H:%M:%S.%f")
    difference = abs(time1 - time2)
    return difference.total_seconds() <= 6*60*60


def convert_to_utc(local_time_str, local_timezone_str):     # I asked ChatGPT for pytz functions/methods
    """
    Convert a local time to UTC time based on the local timezone.

    Args:
    - local_time_str (str): Local time string or dt.datetime (format: "YYYY-MM-DD HH:MM:SS").
    - local_timezone_str (str): Local timezone string (e.g., "Europe/Amsterdam", "Asia/Tokyo").

    Returns:
    - str: UTC time string in "YYYY-MM-DD HH:MM:SS" format.
    """
    # Parse the local time string (if it is a string) into a datetime object
    if isinstance(local_time_str, str):
        try:
            local_time = dt.datetime.strptime(local_time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            local_time = dt.datetime.strptime(local_time_str, "%Y-%m-%d %H:%M")
    else:    # Already a dt.datetime object
        local_time = local_time_str

    # Get the local timezone object
    local_tz = pytz.timezone(local_timezone_str)

    # Attach the local timezone to the local time
    local_time = local_tz.localize(local_time)

    # Convert the localized time to UTC
    utc_time = local_time.astimezone(pytz.utc)

    # Format the UTC datetime as a string without the "+00:00"
    utc_time_str = utc_time.strftime("%Y-%m-%d %H:%M:%S")

    return parse_datetime(utc_time_str)


def utc_to_user_timezone(utc_datetime_str, user_timezone):
    # Parse the UTC datetime string
    utc_datetime = dt.datetime.strptime(utc_datetime_str, '%Y-%m-%d %H:%M:%S')

    # Create a timezone object for the user's timezone
    user_tz = pytz.timezone(user_timezone)

    # Convert the datetime to the user's timezone
    user_datetime = str(utc_datetime.replace(tzinfo=pytz.utc).astimezone(user_tz))

    # :-6 cuz there is a "+hh:mm" in the end of the string, which may confuse an user
    return user_datetime[:-6]
