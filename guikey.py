import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import os
import time
from threading import Thread
from datetime import datetime

# Import all classes from the CLI version
from cli import KeyboardTracker, DatabaseHandler

class KeyboardTrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Keyboard Tracker")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # Initialize tracker and database handler
        self.tracker = KeyboardTracker()
        self.current_user_id = None
        self.current_username = None
        self.is_recording = False
        self.recording_thread = None
        
        # Set up main frame
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.tab_control = ttk.Notebook(self.main_frame)
        
        # Authentication tabs
        self.login_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.login_tab, text="Login")
        
        self.register_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.register_tab, text="Register")
        
        # Tracking tab
        self.tracking_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tracking_tab, text="Tracking")
        
        # History tab
        self.history_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.history_tab, text="History")
        
        # Reports tab
        self.reports_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.reports_tab, text="Reports")
        
        self.tab_control.pack(expand=True, fill=tk.BOTH)
        
        # Set up each tab
        self.setup_login_tab()
        self.setup_register_tab()
        self.setup_tracking_tab()
        self.setup_history_tab()
        self.setup_reports_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready. Please login or register.")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Check login status
        self.check_login_status()
        
        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_login_tab(self):
        """Set up the login tab"""
        frame = ttk.Frame(self.login_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # User info section
        self.user_info_frame = ttk.LabelFrame(frame, text="User Information", padding=10)
        self.user_info_frame.pack(fill=tk.X, pady=10)
        
        self.login_status_var = tk.StringVar()
        self.login_status_var.set("Currently not logged in")
        ttk.Label(self.user_info_frame, textvariable=self.login_status_var, font=("Arial", 10, "bold")).pack(pady=5)
        
        # Login section
        login_frame = ttk.LabelFrame(frame, text="Login to Your Account", padding=10)
        login_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.login_username = ttk.Entry(login_frame, width=30)
        self.login_username.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.login_password = ttk.Entry(login_frame, width=30, show="*")
        self.login_password.grid(row=1, column=1, padx=5, pady=5)
        
        button_frame = ttk.Frame(login_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.login_btn = ttk.Button(button_frame, text="Login", command=self.login)
        self.login_btn.pack(side=tk.LEFT, padx=5)
        
        # Register link
        ttk.Label(button_frame, text="Don't have an account?").pack(side=tk.LEFT, padx=5)
        register_link = ttk.Button(button_frame, text="Register Now", 
                                  command=lambda: self.tab_control.select(1))
        register_link.pack(side=tk.LEFT, padx=5)
        
        # Logout button
        self.logout_btn = ttk.Button(frame, text="Logout", command=self.logout)
        self.logout_btn.pack(pady=10)
        self.logout_btn.config(state=tk.DISABLED)
    
    def setup_register_tab(self):
        """Set up the register tab"""
        frame = ttk.Frame(self.register_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Register section
        register_frame = ttk.LabelFrame(frame, text="Create New Account", padding=10)
        register_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(register_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.register_username = ttk.Entry(register_frame, width=30)
        self.register_username.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(register_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.register_password = ttk.Entry(register_frame, width=30, show="*")
        self.register_password.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(register_frame, text="Confirm Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.register_confirm = ttk.Entry(register_frame, width=30, show="*")
        self.register_confirm.grid(row=2, column=1, padx=5, pady=5)
        
        button_frame = ttk.Frame(register_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        self.register_btn = ttk.Button(button_frame, text="Register", command=self.register)
        self.register_btn.pack(side=tk.LEFT, padx=5)
        
        # Login link
        ttk.Label(button_frame, text="Already have an account?").pack(side=tk.LEFT, padx=5)
        login_link = ttk.Button(button_frame, text="Login Now", 
                               command=lambda: self.tab_control.select(0))
        login_link.pack(side=tk.LEFT, padx=5)
        
        # Registration info
        info_frame = ttk.LabelFrame(frame, text="Registration Information", padding=10)
        info_frame.pack(fill=tk.X, pady=10)
        
        info_text = """
        By registering an account, you'll be able to:
        
        • Track your keyboard usage across sessions
        • View detailed history of your typing patterns
        • Generate reports and analytics
        • Maintain privacy with your personal account
        
        Your data is stored locally and is only accessible to you.
        """
        
        info_label = ttk.Label(info_frame, text=info_text, wraplength=550, justify=tk.LEFT)
        info_label.pack(pady=10)
    
    def setup_tracking_tab(self):
        """Set up the tracking tab with controls and status"""
        frame = ttk.Frame(self.tracking_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Status section
        status_frame = ttk.LabelFrame(frame, text="Tracking Status", padding=10)
        status_frame.pack(fill=tk.X, pady=10)
        
        self.tracking_status_var = tk.StringVar()
        self.tracking_status_var.set("Not recording")
        
        status_label = ttk.Label(status_frame, textvariable=self.tracking_status_var, font=("Arial", 12, "bold"))
        status_label.pack(pady=10)
        
        # Recording indicator
        self.recording_indicator = ttk.Label(status_frame, text="●", font=("Arial", 24))
        self.recording_indicator.pack(pady=5)
        self.update_recording_indicator(False)
        
        # Controls
        control_frame = ttk.LabelFrame(frame, text="Controls", padding=10)
        control_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.start_btn = ttk.Button(control_frame, text="Start Recording", command=self.start_recording)
        self.start_btn.pack(pady=10, fill=tk.X)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Recording", command=self.stop_recording)
        self.stop_btn.pack(pady=10, fill=tk.X)
        self.stop_btn.config(state=tk.DISABLED)
        
        # Instructions
        instructions = """
        Keyboard Tracking Instructions:
        
        1. Click 'Start Recording' to begin tracking keyboard inputs
        2. Press Ctrl+Esc to stop recording at any time
        3. All key presses will be stored to your user account
        4. View your history in the History tab
        5. Generate reports in the Reports tab
        """
        
        instruction_text = scrolledtext.ScrolledText(control_frame, wrap=tk.WORD, height=10)
        instruction_text.pack(pady=10, fill=tk.BOTH, expand=True)
        instruction_text.insert(tk.END, instructions)
        instruction_text.config(state=tk.DISABLED)
    
    def setup_history_tab(self):
        """Set up the history tab with session list and data view"""
        frame = ttk.Frame(self.history_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Session list
        session_frame = ttk.LabelFrame(frame, text="Your Sessions", padding=10)
        session_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Treeview for sessions
        self.session_tree = ttk.Treeview(
            session_frame,
            columns=("id", "start", "end", "log"),
            show="headings",
            selectmode="browse"
        )
        
        # Define columns
        self.session_tree.heading("id", text="Session ID")
        self.session_tree.heading("start", text="Start Time")
        self.session_tree.heading("end", text="End Time")
        self.session_tree.heading("log", text="Log File")
        
        self.session_tree.column("id", width=80, anchor=tk.CENTER)
        self.session_tree.column("start", width=150)
        self.session_tree.column("end", width=150)
        self.session_tree.column("log", width=250)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(session_frame, orient=tk.VERTICAL, command=self.session_tree.yview)
        self.session_tree.configure(yscroll=scrollbar.set)
        
        # Pack everything
        self.session_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.refresh_btn = ttk.Button(button_frame, text="Refresh Sessions", command=self.refresh_sessions)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        self.view_db_btn = ttk.Button(button_frame, text="View Database Data", command=lambda: self.view_session_data("db"))
        self.view_db_btn.pack(side=tk.LEFT, padx=5)
        
        self.view_file_btn = ttk.Button(button_frame, text="View Log File", command=lambda: self.view_session_data("file"))
        self.view_file_btn.pack(side=tk.LEFT, padx=5)
        
        # Session data view
        data_frame = ttk.LabelFrame(frame, text="Session Data", padding=10)
        data_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.data_text = scrolledtext.ScrolledText(data_frame, wrap=tk.WORD)
        self.data_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_reports_tab(self):
        """Set up the reports tab with session selection and report view"""
        frame = ttk.Frame(self.reports_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Session selection
        select_frame = ttk.LabelFrame(frame, text="Select Session", padding=10)
        select_frame.pack(fill=tk.X, pady=10)
        
        self.report_sessions_var = tk.StringVar()
        self.report_sessions = ttk.Combobox(select_frame, textvariable=self.report_sessions_var, state="readonly")
        self.report_sessions.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.generate_btn = ttk.Button(select_frame, text="Generate Report", command=self.generate_report)
        self.generate_btn.pack(side=tk.LEFT, padx=5)
        
        # Report view
        report_frame = ttk.LabelFrame(frame, text="Report", padding=10)
        report_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.report_text = scrolledtext.ScrolledText(report_frame, wrap=tk.WORD)
        self.report_text.pack(fill=tk.BOTH, expand=True)
    
    def check_login_status(self):
        """Update UI based on login status"""
        if self.current_user_id:
            self.login_status_var.set(f"Logged in as: {self.current_username}")
            self.logout_btn.config(state=tk.NORMAL)
            self.start_btn.config(state=tk.NORMAL)
            self.refresh_sessions()
            self.refresh_report_sessions()
            
            # Switch to tracking tab after successful login
            self.tab_control.select(2)  # Index 2 is the tracking tab (after login and register)
        else:
            self.login_status_var.set("Currently not logged in")
            self.logout_btn.config(state=tk.DISABLED)
            self.start_btn.config(state=tk.DISABLED)
            # Clear session data
            self.session_tree.delete(*self.session_tree.get_children())
            self.data_text.delete(1.0, tk.END)
            self.report_text.delete(1.0, tk.END)
            self.report_sessions.set('')
            self.report_sessions['values'] = []
    
    def register(self):
        """Register a new user"""
        username = self.register_username.get().strip()
        password = self.register_password.get()
        confirm = self.register_confirm.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        success = self.tracker.db.register_user(username, password)
        
        if success:
            messagebox.showinfo("Success", f"User '{username}' registered successfully! Please login to continue.")
            self.register_username.delete(0, tk.END)
            self.register_password.delete(0, tk.END)
            self.register_confirm.delete(0, tk.END)
            # Switch to login tab after successful registration
            self.tab_control.select(0)
        else:
            messagebox.showerror("Error", "Registration failed. Username may already exist.")
    
    def login(self):
        """Login user"""
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
        
        user_id, username = self.tracker.db.authenticate_user(username, password)
        
        if user_id:
            self.current_user_id = user_id
            self.current_username = username
            self.status_var.set(f"Logged in as {username}")
            self.check_login_status()
            messagebox.showinfo("Success", f"Welcome, {username}!")
            self.login_username.delete(0, tk.END)
            self.login_password.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Invalid username or password")
    
    def logout(self):
        """Logout user"""
        if self.is_recording:
            self.stop_recording()
        
        self.current_user_id = None
        self.current_username = None
        self.status_var.set("Logged out")
        
        self.check_login_status()
        messagebox.showinfo("Logged Out", "You have been logged out")
        
        # Switch back to login tab after logout
        self.tab_control.select(0)
    
    def start_recording(self):
        """Start keyboard recording in a separate thread"""
        if not self.current_user_id:
            messagebox.showerror("Error", "You must be logged in to start tracking")
            return
        
        if self.is_recording:
            messagebox.showinfo("Info", "Already recording")
            return
        
        # Create and start recording thread
        self.recording_thread = Thread(target=self._recording_thread_func)
        self.recording_thread.daemon = True
        self.recording_thread.start()
        
        self.is_recording = True
        self.update_tracking_ui(True)
    
    def _recording_thread_func(self):
        """Function for recording thread to avoid UI freezing"""
        try:
            self.tracker.start_recording(self.current_user_id, self.current_username)
        except Exception as e:
            print(f"Recording error: {e}")
            # Update UI on the main thread
            self.root.after(0, self.handle_recording_error, str(e))
    
    def handle_recording_error(self, error_msg):
        """Handle recording errors on the main thread"""
        messagebox.showerror("Recording Error", f"An error occurred: {error_msg}")
        self.is_recording = False
        self.update_tracking_ui(False)
    
    def stop_recording(self):
        """Stop keyboard recording"""
        # Find the user log file
        if self.current_user_id in self.tracker.user_log_files:
            user_log_file = self.tracker.user_log_files[self.current_user_id]
            self.tracker.stop_recording(user_log_file)
        
        self.is_recording = False
        self.update_tracking_ui(False)
    
    def update_tracking_ui(self, recording):
        """Update UI based on recording status"""
        if recording:
            self.tracking_status_var.set("Recording in progress")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.update_recording_indicator(True)
            self.status_var.set("Recording keyboard inputs... Press Ctrl+Esc to stop.")
        else:
            self.tracking_status_var.set("Not recording")
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.update_recording_indicator(False)
            self.status_var.set("Ready")
            # Refresh data
            self.refresh_sessions()
            self.refresh_report_sessions()
    
    def update_recording_indicator(self, active):
        """Update the recording indicator color"""
        if active:
            self.recording_indicator.config(foreground="red")
        else:
            self.recording_indicator.config(foreground="gray")
    
    def refresh_sessions(self):
        """Refresh the session list in the history tab"""
        if not self.current_user_id:
            return
        
        # Clear existing data
        self.session_tree.delete(*self.session_tree.get_children())
        
        # Get sessions
        sessions = self.tracker.db.get_user_sessions(self.current_user_id)
        
        if not sessions:
            self.data_text.delete(1.0, tk.END)
            self.data_text.insert(tk.END, "No sessions found")
            return
        
        # Add sessions to tree
        for session_id, start_time, end_time, log_file in sessions:
            end_str = end_time if end_time else "Still active"
            self.session_tree.insert("", tk.END, values=(session_id, start_time, end_str, log_file))
    
    def view_session_data(self, data_source):
        """View session data from database or file"""
        selected = self.session_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a session first")
            return
        
        # Get selected session details
        session_id = self.session_tree.item(selected, "values")[0]
        log_file = self.session_tree.item(selected, "values")[3]
        
        # Clear data view
        self.data_text.delete(1.0, tk.END)
        
        if data_source == "db":
            # Get data from database
            data = self.tracker.db.get_session_data(session_id)
            if data:
                self.data_text.insert(tk.END, "=== Tracked Data from Database ===\n")
                for data_type, content, timestamp in data:
                    self.data_text.insert(tk.END, f"{timestamp}: [{data_type}] {content}\n")
            else:
                self.data_text.insert(tk.END, "No data found for this session in database.")
                
        elif data_source == "file":
            # Get data from log file
            try:
                if os.path.exists(log_file):
                    with open(log_file, "r") as f:
                        lines = f.readlines()
                        self.data_text.insert(tk.END, "=== Tracked Data from File ===\n")
                        for line in lines:
                            self.data_text.insert(tk.END, line)
                else:
                    self.data_text.insert(tk.END, f"Log file not found: {log_file}")
            except Exception as e:
                self.data_text.insert(tk.END, f"Error reading log file: {e}")
    
    def refresh_report_sessions(self):
        """Refresh the session dropdown in the reports tab"""
        if not self.current_user_id:
            return
        
        # Get sessions
        sessions = self.tracker.db.get_user_sessions(self.current_user_id)
        
        if not sessions:
            self.report_sessions['values'] = []
            self.report_sessions.set('')
            return
        
        # Create session options
        options = []
        self.session_data = {}
        
        for session_id, start_time, end_time, _ in sessions:
            end_str = end_time if end_time else "Still active"
            option = f"Session {session_id} - {start_time} to {end_str}"
            options.append(option)
            self.session_data[option] = session_id
        
        self.report_sessions['values'] = options
        if options:
            self.report_sessions.current(0)
    
    def generate_report(self):
        """Generate a report for the selected session"""
        selected = self.report_sessions.get()
        
        if not selected:
            messagebox.showinfo("Info", "Please select a session first")
            return
        
        session_id = self.session_data.get(selected)
        if not session_id:
            return
        
        # Get report
        report = self.tracker.db.generate_data_report(session_id)
        
        # Show report
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(tk.END, report)
    
    def on_close(self):
        """Handle window close event"""
        if self.is_recording:
            if messagebox.askyesno("Confirm", "Recording is in progress. Stop recording and exit?"):
                self.stop_recording()
                self.tracker.db.close_connection()
                self.root.destroy()
        else:
            self.tracker.db.close_connection()
            self.root.destroy()

# Ensure we can run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = KeyboardTrackerGUI(root)
    root.mainloop()