import sqlite3
from flask import *
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler   # watched a YT tutorial and read documentation
from pytz import utc

from helpers import *
from keys import SECRET_KEY

"""
users.db .schema:
     
CREATE TABLE tasks (user_id INTEGER,
task_n INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
task_title TEXT NOT NULL,
task TEXT,
task_dt TEXT NOT NULL,
deadline TEXT NOT NULL,
reminders1 TEXT,
reminders2 TEXT,
reminders3 TEXT,
reminders4 TEXT,
reminders5 TEXT,
send INTEGER DEFAULT 0,
FOREIGN KEY(user_id) REFERENCES users(id));

CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
timezone TEXT DEFAULT "Etc/GMT",
token TEXT,
username TEXT NOT NULL,
hash TEXT NOT NULL,
mail TEXT,
verified INTEGER DEFAULT 0,
token_time TEXT);
"""


class Config:   # Asked ChatGPT for this class
    SCHEDULER_API_ENABLED = True
    JOBS_TIMEZONE = 'UTC'


app = Flask(__name__, template_folder='templates', static_folder='static')

# Configure session to use filesystem (instead of signed cookies)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
app.config['SECRET_KEY'] = SECRET_KEY
app.config.from_object(Config())    # Asked ChatGPT for this config line

# Set background tasks (scheduled email sending)
sched = BackgroundScheduler(timezone=utc)
sched.start()


# Set database
con = sqlite3.connect("users.db", check_same_thread=False)
db = con.cursor()


def schedule_email(email_datetime, obj, body, recipient):
    # Schedule the send_email_task to run at the specified datetime
    sched.add_job(id=generate_token(6), func=send_mail, trigger='date', run_date=email_datetime, args=[obj, body, recipient])


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register"""
    session.clear()

    if request.method == "POST":
        # Validate input fields
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not (username and password and confirmation):
            return render_template("register.html", notAllFields=True)

        if password != confirmation:
            return render_template("register.html", diffPaswords=True)

        if len(password) < 8 or len(password) > 32:
            return render_template("register.html", noRequirements=True)

        # Validate password requirements: letters, numbers, and special characters
        has_letters = any(char.isalpha() for char in password)
        has_numbers = any(char.isdigit() for char in password)
        has_specials = any(not char.isalnum() and char != " " for char in password)

        if not (has_letters and has_numbers and has_specials):
            return render_template("register.html", noRequirements=True)

        # Check if the username already exists
        existing_user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            return render_template("register.html", userExists=True)

        # Insert the new user into the database
        hashed_password = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (username, hashed_password))
        con.commit()

        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not (username and password):
            return render_template("login.html", notAllFields=True)

        user_data = db.execute("SELECT id, hash FROM users WHERE username = ?", (username,)).fetchone()
        if not user_data or not check_password_hash(user_data[1], password):  # Access hash
            return render_template("login.html", invalidCredentials=True)

        session["user_id"] = user_data[0]  # Access id using index 0
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/")
@login_required
def home():
    """Display tasks with a non-expired deadline"""

    user_id = session["user_id"]
    rn = datetime.utcnow()

    # Fetch and filter tasks with a deadline greater than the current time
    tasks = db.execute("SELECT * FROM tasks WHERE user_id = ? AND deadline > ?", (user_id, rn)).fetchall()
    deadlines = db.execute("SELECT deadline FROM tasks WHERE user_id = ? AND deadline > ?", (user_id, rn)).fetchall()
    timezone = db.execute("SELECT timezone FROM users WHERE id = ?", (user_id,)).fetchone()[0]
    u_timezone_deadlines = [utc_to_user_timezone(i[0], timezone) for i in deadlines]

    # Remove tasks with an expired deadline from the database
    db.execute("DELETE FROM tasks WHERE user_id = ? AND deadline <= ?", (user_id, rn))
    con.commit()

    user_email_row = db.execute("SELECT mail FROM users WHERE id = ? AND verified = 1", (user_id,)).fetchone()

    if user_email_row:    # if (verified) email exists
        user_email = user_email_row[0]  # Unpack the email from the tuple
        all_reminders_notification_on_tuples = db.execute("SELECT reminders1, reminders2, reminders3, reminders4, reminders5, deadline, task_n FROM tasks WHERE user_id = ? AND send = 1", (user_id,)).fetchall()
        # print(all_reminders_notification_on_tuples) <-- Needed to debug

        all_reminders = []  # Initialize list to store all reminders with their task number

        for reminder_data in all_reminders_notification_on_tuples:  # I asked chat GPT for this loop
            task_n = reminder_data[-1]  # Extract the task number from the reminder data
            reminders = reminder_data[:-1]  # Extract the reminder datetimes
            all_reminders.extend([Reminder(reminder_datetime, task_n) for reminder_datetime in reminders if reminder_datetime is not None])  # Assign correct task number

        #print(all_reminders) <-- Needed to debug

        # Send emails for reminders
        for reminder in all_reminders:
            # Fetch task details from the database
            task_info = db.execute("SELECT task_title, task, deadline FROM tasks WHERE user_id = ? AND task_n = ?", (user_id, reminder.task_n)).fetchone()

            if task_info:
                task_title = task_info[0]
                task_description = task_info[1]
                task_deadline = task_info[2]

                username = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()[0]
                body = f"Heya {username}!\nYou have a task with deadline \"{task_deadline}\" to get done!\nYou have to:\n\"{task_description}\""
                print(reminder.reminder)

                schedule_email(reminder.reminder, f"Task \"{task_title}\" Reminder", body, user_email)
            else:
                # Handle the case where no task details are found
                print(f"No task found with task_n: {reminder.task_n}")

    # Prepare data for rendering (asked Chat GPT for this loop)
    task_data = []
    for task, deadline in zip(tasks, u_timezone_deadlines):
        task_data.append((task[1], task[2], deadline))

    return render_template("tasks.html", task_data=task_data)


@app.route("/task/<int:task_number>")   # Discovered how to pass values by URL thanks to ChatGPT
@login_required
def task_details(task_number):
    """Display details of a specific task"""

    user_id = session["user_id"]
    task = db.execute("SELECT * FROM tasks WHERE user_id = ? AND task_n = ?", (user_id, task_number)).fetchone()
    timezone = db.execute("SELECT timezone FROM users WHERE id = ?", (user_id,)).fetchone()[0]

    if not task:
        # Handle task not found
        return error("Task not found", 404)

    return render_template("task_details.html", task=task, utc_to_user_timezone=utc_to_user_timezone, user_timezone=timezone, task_number=task_number)  # Pass task_number to the template


@app.route("/notifications/<int:task_number>", methods=["GET", "POST"])
@login_required
def nft(task_number):
    user_id = session["user_id"]

    # Fetch the task and valid_reminders from the database
    task = db.execute("SELECT * FROM tasks WHERE task_n = ?", (task_number,)).fetchone()
    reminders = [task[i + 6] for i in range(5) if task[i + 6] and task[i + 6].strip()]

    rn = datetime.utcnow()
    timezone = db.execute("SELECT timezone FROM users WHERE id = ?", (user_id,)).fetchone()[0]

    task_deadline = datetime.strptime(task[5], "%Y-%m-%d %H:%M:%S")

    # List to store valid reminders
    valid_reminders = []

    for i, r in enumerate(reminders, start=1):
        if r:
            reminder_datetime = parse_datetime(remove_t(r))
            reminder_datetime = convert_to_utc(reminder_datetime, timezone)
            if reminder_datetime < rn or reminder_datetime > task_deadline:
                # Remove the reminder from the database
                db.execute(f"UPDATE tasks SET reminders{i} = NULL WHERE task_n = ? AND reminders{i} = ?", (task_number, r))
                con.commit()
            else:
                valid_reminders.append(r)
                # Store the reminder in the database
                db.execute(f"UPDATE tasks SET reminders{i} = ? WHERE task_n = ? AND user_id = ?", (reminder_datetime, task_number, user_id))
                con.commit()
        else:
            # Handle the case where the reminder is None
            valid_reminders.append(None)

    return render_template("notifications.html", task=task, reminders=valid_reminders)


@app.route("/save_reminders/<int:task_number>", methods=["POST"])
@login_required
def save_reminders(task_number):
    # Get the reminders from the form data
    reminders = [request.form.get(f"reminder{i+1}") for i in range(5)]

    # Update the reminders in the database
    for i, reminder_datetime in enumerate(reminders, start=1):
        reminder_column = f"reminders{i}"  # Construct the column name
        if reminder_datetime:
            reminder_datetime = remove_t(reminder_datetime)
            if parse_datetime(reminder_datetime) < datetime.utcnow():
                return error(f"Reminders cannot be before now and/or after the deadline. ({reminder_datetime} invalid)")
            db.execute(f"UPDATE tasks SET {reminder_column} = ? WHERE task_n = ?", (reminder_datetime, task_number))
        else:
            db.execute(f"UPDATE tasks SET {reminder_column} = NULL WHERE task_n = ?", (task_number,))

    con.commit()

    return redirect(url_for('nft', task_number=task_number))    # ChatGPT made me learn url_for() function


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Add task"""
    if request.method == "POST":
        rn = datetime.utcnow()  # get current UTC time

        if merge_date_time(request.form.get("date"), request.form.get("time")) <= rn:
            return error("Deadline cannot be earlier than now.")

        user_id = session["user_id"]
        timezone = db.execute("SELECT timezone FROM users WHERE id = ?", (user_id,)).fetchone()[0]

        db.execute(
            "INSERT INTO tasks(user_id, task_title, task, task_dt, deadline) VALUES(?, ?, ?, ?, ?)",
            (user_id, request.form.get("title"), request.form.get("desc"), rn,
             convert_to_utc(merge_date_time(request.form.get("date"), request.form.get("time")), timezone))
        )

        con.commit()

        return redirect("/")

    else:
        return render_template("add.html")


@app.route("/delete_task/<int:task_number>", methods=["POST"])
@login_required
def delete_task(task_number):
    """ Delete a specific task """

    user_id = session['user_id']
    db.execute("DELETE FROM tasks WHERE user_id = ? AND task_n = ?", (user_id, task_number))

    con.commit()

    return redirect('/')


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/set_notifications")
@login_required
def set_nft():
    """Display tasks (with a non-expired deadline) with 2 buttons each: set notifications on and off"""

    user_id = session["user_id"]
    rn = datetime.utcnow()
    timezone = db.execute("SELECT timezone FROM users WHERE id = ?", (user_id,)).fetchone()[0]

    # Fetch and filter tasks with a deadline greater than the current time
    tasks = db.execute("SELECT * FROM tasks WHERE user_id = ? AND deadline > ?", (user_id, rn)).fetchall()

    return render_template("triggerNft.html", tasks=tasks, utc_to_user_timezone=utc_to_user_timezone, user_timezone=timezone)


@app.route("/toggle_on_task_notifications/<int:task_number>", methods=["POST"])
@login_required
def task_nft_on(task_number):
    """ Turn on a specific task's reminders' e-mails """

    user_id = session['user_id']
    tasks = db.execute("SELECT * FROM tasks WHERE user_id = ?", (user_id,)).fetchall()
    timezone = db.execute("SELECT timezone FROM users WHERE id = ?", (user_id,)).fetchone()[0]

    # set send column to 1 (True)
    db.execute("UPDATE tasks SET send = 1 WHERE task_n = ? AND user_id = ?", (task_number, user_id))
    con.commit()

    return render_template("triggerNft.html", tasks=tasks, utc_to_user_timezone=utc_to_user_timezone, user_timezone=timezone)


@app.route("/toggle_off_notifications/<int:task_number>", methods=["POST"])
@login_required
def task_nft_off(task_number):
    """ Turn off a specific task's reminders' e-mails """

    user_id = session['user_id']
    tasks = db.execute("SELECT * FROM tasks WHERE user_id = ?", (user_id,)).fetchall()
    timezone = db.execute("SELECT timezone FROM users WHERE id = ?", (user_id,)).fetchone()[0]

    # set send column to 0 (False)
    db.execute("UPDATE tasks SET send = 0 WHERE task_n = ? AND user_id = ?", (task_number, user_id))
    con.commit()

    return render_template("triggerNft.html", tasks=tasks, utc_to_user_timezone=utc_to_user_timezone, user_timezone=timezone)


@app.route("/verify_email", methods=["GET", "POST"])
@login_required
def verify_email():
    """Verify email by sent token and user input"""
    user_id = session['user_id']

    user_mail = db.execute("SELECT mail FROM users WHERE id = ?", (user_id,)).fetchone()
    is_verified = db.execute("SELECT verified FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_mail:  # Mail not set
        return redirect("/set_email")
    elif is_verified[0]:  # Already verified
        return render_template("verifyEmail.html", verified=True)
    if request.method == "POST":
        token = request.form.get("token")
        database_token, token_time = db.execute("SELECT token, token_time FROM users WHERE id = ?", (user_id,)).fetchone()
        if not token or token != database_token:
            return error("Tokens do not match")
        if not is_within_six_hours(datetime.utcnow(), token_time):
            return error("Token expired", 403)

        # If tokens match and not expired, set user mail as verified and remove the token
        db.execute("UPDATE users SET verified = 1, token = NULL, token_time = NULL WHERE id = ?", (user_id,))
        con.commit()
        return render_template("verifyEmail.html", verified=True)

    return render_template("verifyEmail.html", verified=False, email=user_mail[0])


@app.route("/send_token", methods=["POST"])
@login_required
def send_token():
    """Store generated token and its generation time in the database"""
    user_id = session['user_id']
    token, token_time = generate_token_by_rn()
    db.execute("UPDATE users SET token = ?, token_time = ? WHERE id = ?", (token, token_time, user_id))
    con.commit()

    # send verification token
    send_mail("Haxxor Task Manager mail verification token",
              f"Heya {db.execute('SELECT username FROM users where id = ?', (user_id,)).fetchone()[0]}, here is your token:\n{token}\n Thank you for choosing HX Task Manager!",
              db.execute("SELECT mail FROM users where id = ?", (user_id,)).fetchone()[0])

    return render_template("verifyEmail.html", verified=False)


@app.route("/set_email", methods=["GET", "POST"])
@login_required
def set_email():
    """Save user mail on the database"""

    if request.method == "POST":
        user_id = session['user_id']
        user_email = request.form.get("email")

        # save user_mail on the database (not yet verified)
        db.execute("UPDATE users SET mail = ?, verified = 0 WHERE id = ?", (user_email, user_id))
        con.commit()

    return render_template("setEmail.html")


@app.route("/set_timezone", methods=["GET", "POST"])
@login_required
def set_timezone():
    """set user timezone for reminders"""

    timezone = request.form.get("timezone")     # Get user's input timezone

    if request.method == "GET" or not timezone:     # If GET method or invalid timezone
        return render_template("timezone.html")

    else:   # If POST and valid input, store timezone in database
        db.execute("UPDATE users SET timezone = ?", (timezone,))
        con.commit()
        return redirect("/")


if __name__ == '__main__':
    app.run()
