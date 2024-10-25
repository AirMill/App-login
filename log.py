import tkinter as tk
from tkinter import messagebox, scrolledtext
import sqlite3
import psutil
import time
import threading

# Global variable to control logging thread
stop_logging_flag = False

# Create or connect to an SQLite database
def create_database():
    conn = sqlite3.connect('app_logs.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        app_name TEXT,
                        log_time TEXT,
                        cpu_usage REAL,
                        memory_usage REAL
                      )''')
    conn.commit()
    conn.close()

# Function to get the running processes, with non-system apps on top
def get_running_apps():
    apps = []
    non_system_apps = []
    system_apps = []

    for process in psutil.process_iter(['pid', 'name', 'username']):
        try:
            if process.info['username'] == psutil.Process().username():
                non_system_apps.append(f"{process.info['name']} (PID: {process.info['pid']})")
            else:
                system_apps.append(f"{process.info['name']} (PID: {process.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    non_system_apps.sort()
    system_apps.sort()

    apps = non_system_apps + system_apps
    return apps

# Log the app usage data to the database
def log_app_usage(app_name, pid):
    conn = sqlite3.connect('app_logs.db')
    cursor = conn.cursor()

    try:
        process = psutil.Process(pid)
        cpu_usage = process.cpu_percent(interval=1)
        memory_usage = process.memory_info().rss / (1024 * 1024)  # Convert to MB
        log_time = time.strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("INSERT INTO logs (app_name, log_time, cpu_usage, memory_usage) VALUES (?, ?, ?, ?)",
                       (app_name, log_time, cpu_usage, memory_usage))
        conn.commit()
    except psutil.NoSuchProcess:
        messagebox.showerror("Error", "The selected process no longer exists.")
    finally:
        conn.close()

# Function to start logging for the selected app
def start_logging(app_selection, start_button, stop_button):
    global stop_logging_flag
    stop_logging_flag = False

    if not app_selection:
        messagebox.showerror("Error", "No app selected.")
        return

    app_name, pid = app_selection.rsplit(" (PID: ", 1)
    pid = int(pid[:-1])

    # Disable the Start button and enable the Stop button
    start_button.config(state='disabled')
    stop_button.config(state='normal')

    def log_thread():
        while not stop_logging_flag:
            log_app_usage(app_name, pid)
            time.sleep(5)

    threading.Thread(target=log_thread, daemon=True).start()

# Function to stop logging
def stop_logging(start_button, stop_button):
    global stop_logging_flag
    stop_logging_flag = True

    start_button.config(state='normal')
    stop_button.config(state='disabled')

    messagebox.showinfo("Stopped", "Logging has been stopped.")

# Function to check if the app had internet connections
def has_internet_connections(pid):
    try:
        connections = psutil.Process(pid).connections(kind='inet')
        return len(connections) > 0
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

# Function to show detailed log information
def show_log_details(log):
    app_name, log_time, cpu_usage, memory_usage = log[1], log[2], log[3], log[4]

    details_window = tk.Toplevel()
    details_window.title("Log Details")
    details_window.geometry("400x250")

    pid = None
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == app_name:
            pid = proc.info['pid']
            break

    internet_status = "Yes" if pid and has_internet_connections(pid) else "No"

    details_text = f"App Name: {app_name}\n\n" \
                   f"Time: {log_time}\n" \
                   f"CPU Usage: {cpu_usage}%\n" \
                   f"Memory Usage: {memory_usage} MB\n" \
                   f"Internet Connections: {internet_status}"

    tk.Label(details_window, text=details_text, anchor='w', justify=tk.LEFT).pack(padx=10, pady=10)

# Function to review logs in a new window with clickable entries
def review_logs():
    conn = sqlite3.connect('app_logs.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs")
    logs = cursor.fetchall()
    conn.close()

    log_window = tk.Toplevel()
    log_window.title("App Logs")
    log_window.geometry("500x400")

    log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, width=60, height=20)
    log_text.pack(padx=10, pady=10)

    # Insert logs and make them clickable
    for idx, log in enumerate(logs):
        # Format: Log Number - Date - Time - App Name
        log_number = log[0]
        log_time = log[2].split(' ')  # Get date and time separately
        log_date = log_time[0]
        log_time = log_time[1]
        app_name = log[1]

        log_line = f"Log {log_number} - {log_date} - {log_time} - {app_name}\n"
        start_idx = log_text.index(tk.END)
        log_text.insert(tk.END, log_line)
        end_idx = log_text.index(tk.END)

        tag = f"log_{log[0]}"  # Unique tag for each log entry
        log_text.tag_add(tag, start_idx, end_idx)
        log_text.tag_config(tag, foreground="blue", underline=True)  # Make it look like a link
        log_text.tag_bind(tag, '<Button-1>', lambda event, log=log: show_log_details(log))

    log_text.config(state=tk.DISABLED)  # Disable text editing

# GUI code using Tkinter
def create_gui():
    root = tk.Tk()
    root.title("App Logger")
    root.geometry("400x350")

    tk.Label(root, text="Select an App to Log").pack(pady=10)

    app_var = tk.StringVar()
    apps_menu = tk.OptionMenu(root, app_var, *get_running_apps())
    apps_menu.pack(pady=10)

    def refresh_apps():
        app_var.set('')
        apps_menu['menu'].delete(0, 'end')
        for app in get_running_apps():
            apps_menu['menu'].add_command(label=app, command=tk._setit(app_var, app))

    tk.Button(root, text="Refresh Apps", command=refresh_apps).pack(pady=5)

    start_button = tk.Button(root, text="Start Logging", command=lambda: start_logging(app_var.get(), start_button, stop_button))
    start_button.pack(pady=5)

    stop_button = tk.Button(root, text="Stop Logging", state='disabled', command=lambda: stop_logging(start_button, stop_button))
    stop_button.pack(pady=5)

    tk.Button(root, text="Review Logs", command=review_logs).pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    create_database()
    create_gui()
