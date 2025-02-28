import keyboard
import time
import mysql.connector
import hashlib
import getpass
import os
from datetime import datetime

class KeyboardTracker:
    def __init__(self, log_file="keyboard_log.txt"):
        self.log_file = log_file
        self.recording = False
        self.db = DatabaseHandler()
        self.current_user_id = None
        self.session_id = None
        self.tracking_data = []
        self.user_log_files = {}  # Dictionary to store log file paths for each user
        
    def start_recording(self, user_id, username):
        """Start recording keyboard inputs"""
        self.current_user_id = user_id
        self.recording = True
        self.tracking_data = []
        
        # Use one consistent file for each user
        if user_id not in self.user_log_files:
            # Create user log file if it doesn't exist
            user_log_file = f"user_{username}_{user_id}_log.txt"
            self.user_log_files[user_id] = user_log_file
        
        user_log_file = self.user_log_files[user_id]
        full_log_path = os.path.abspath(user_log_file)
        
        # Create a new session for this recording
        self.session_id = self.db.create_session(user_id, full_log_path)
        
        print("Recording started. Press Ctrl+Esc to stop.")
        
        # Append session start to log file
        with open(user_log_file, "a") as f:
            f.write(f"\n\n=== New Session Started: {datetime.now()} ===\n")
                
        # Start keyboard listener
        keyboard.on_release(callback=self.on_key_event)
        
        # Keep the program running
        keyboard.wait('ctrl+esc')
        self.stop_recording(user_log_file)
        
    def stop_recording(self, user_log_file):
        """Stop recording keyboard inputs"""
        self.recording = False
        keyboard.unhook_all()
        
        # Save collected data to the database
        if self.tracking_data and self.session_id:
            self.db.store_tracking_data(self.session_id, self.tracking_data)
        
        # Write session end marker to log file
        with open(user_log_file, "a") as f:
            f.write(f"=== Session Ended: {datetime.now()} ===\n")
            
        print(f"Recording stopped. Log saved to {user_log_file} and database.")
        # End the session
        if self.session_id:
            self.db.end_session(self.session_id)
        
    def on_key_event(self, event):
        """Callback function for keyboard events"""
        if self.recording and self.current_user_id in self.user_log_files:
            key_name = event.name
            # Format special keys
            if len(key_name) > 1:
                key_name = f"[{key_name}]"
                
            # Get current timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Collect data for batch database insert
            self.tracking_data.append((key_name, timestamp))
            
            # If we have a lot of data, store it in batches
            if len(self.tracking_data) >= 50:
                self.db.store_tracking_data(self.session_id, self.tracking_data)
                self.tracking_data = []
            
            # Log to the user's persistent log file
            user_log_file = self.user_log_files[self.current_user_id]
            with open(user_log_file, "a") as f:
                f.write(f"{timestamp}: {key_name}\n")


class DatabaseHandler:
    def __init__(self):
        self.host = "localhost"
        self.user = "root"
        self.password = ""  # Default XAMPP MySQL password is empty
        self.database = "keytracker_db"
        self.conn = None
        
        try:
            # Connect to MySQL server
            self.conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password
            )
            self.cursor = self.conn.cursor()
            
            # Create database if not exists
            self.cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
            self.cursor.execute(f"USE {self.database}")
            
            # Create users table if not exists
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create sessions table to track logging sessions
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP NULL,
                    log_file_path VARCHAR(255) NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Create tracked_data table to store keyboard inputs in batches
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracked_data (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    session_id INT NOT NULL,
                    data_type VARCHAR(20) NOT NULL,
                    data_content TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                )
            ''')
            
            self.conn.commit()
            print("Database connection established and tables created successfully.")
            
        except mysql.connector.Error as err:
            print(f"Database Error: {err}")
    
    def close_connection(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()
            print("Database connection closed.")
    
    def hash_password(self, password):
        """Hash the password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, username, password):
        """Register a new user"""
        try:
            hashed_password = self.hash_password(password)
            query = "INSERT INTO users (username, password) VALUES (%s, %s)"
            self.cursor.execute(query, (username, hashed_password))
            self.conn.commit()
            print(f"User '{username}' registered successfully!")
            return True
        except mysql.connector.Error as err:
            print(f"Registration error: {err}")
            return False
    
    def authenticate_user(self, username, password):
        """Authenticate a user and return user_id if successful"""
        try:
            hashed_password = self.hash_password(password)
            query = "SELECT id FROM users WHERE username = %s AND password = %s"
            self.cursor.execute(query, (username, hashed_password))
            user = self.cursor.fetchone()
            
            if user:
                print(f"User '{username}' authenticated successfully!")
                return user[0], username  # Return user_id and username
            else:
                print("Invalid username or password.")
                return None, None
                
        except mysql.connector.Error as err:
            print(f"Authentication error: {err}")
            return None, None
    
    def create_session(self, user_id, log_file_path):
        """Create a new session for the user and return session_id"""
        try:
            query = "INSERT INTO sessions (user_id, log_file_path) VALUES (%s, %s)"
            self.cursor.execute(query, (user_id, log_file_path))
            self.conn.commit()
            return self.cursor.lastrowid  # Return the session_id
        except mysql.connector.Error as err:
            print(f"Session creation error: {err}")
            return None
    
    def end_session(self, session_id):
        """Mark the end time of a session"""
        try:
            query = "UPDATE sessions SET end_time = CURRENT_TIMESTAMP WHERE id = %s"
            self.cursor.execute(query, (session_id,))
            self.conn.commit()
        except mysql.connector.Error as err:
            print(f"Session end error: {err}")
    
    def store_tracking_data(self, session_id, tracking_data):
        """Store tracking data in the database"""
        if not tracking_data:
            return
            
        try:
            # Insert multiple rows at once for better performance
            query = "INSERT INTO tracked_data (session_id, data_type, data_content, timestamp) VALUES (%s, %s, %s, %s)"
            data_rows = []
            
            for key, timestamp in tracking_data:
                data_rows.append((session_id, "keypress", key, timestamp))
                
            self.cursor.executemany(query, data_rows)
            self.conn.commit()
        except mysql.connector.Error as err:
            print(f"Store tracking data error: {err}")
    
    def get_user_sessions(self, user_id):
        """Get all sessions for a user"""
        try:
            query = """
                SELECT id, start_time, end_time, log_file_path 
                FROM sessions 
                WHERE user_id = %s 
                ORDER BY start_time DESC
            """
            self.cursor.execute(query, (user_id,))
            return self.cursor.fetchall()
        except mysql.connector.Error as err:
            print(f"Get sessions error: {err}")
            return []
    
    def get_session_data(self, session_id):
        """Get tracked data for a session"""
        try:
            query = """
                SELECT data_type, data_content, timestamp 
                FROM tracked_data 
                WHERE session_id = %s 
                ORDER BY timestamp ASC
            """
            self.cursor.execute(query, (session_id,))
            return self.cursor.fetchall()
        except mysql.connector.Error as err:
            print(f"Get tracked data error: {err}")
            return []
    
    def get_username(self, user_id):
        """Get username for a user_id"""
        try:
            query = "SELECT username FROM users WHERE id = %s"
            self.cursor.execute(query, (user_id,))
            result = self.cursor.fetchone()
            if result:
                return result[0]
            return None
        except mysql.connector.Error as err:
            print(f"Get username error: {err}")
            return None
    
    def generate_data_report(self, session_id):
        """Generate a summary report of tracked data for a session"""
        try:
            # Get session details
            query = "SELECT start_time, end_time, user_id FROM sessions WHERE id = %s"
            self.cursor.execute(query, (session_id,))
            session_details = self.cursor.fetchone()
            
            if not session_details:
                return "Session not found"
                
            start_time, end_time, user_id = session_details
            
            # Get username
            query = "SELECT username FROM users WHERE id = %s"
            self.cursor.execute(query, (user_id,))
            username = self.cursor.fetchone()[0]
            
            # Count total keypresses
            query = "SELECT COUNT(*) FROM tracked_data WHERE session_id = %s"
            self.cursor.execute(query, (session_id,))
            total_keypresses = self.cursor.fetchone()[0]
            
            # Get most common keypresses
            query = """
                SELECT data_content, COUNT(*) as count 
                FROM tracked_data 
                WHERE session_id = %s 
                GROUP BY data_content 
                ORDER BY count DESC 
                LIMIT 5
            """
            self.cursor.execute(query, (session_id,))
            common_keys = self.cursor.fetchall()
            
            # Generate report
            report = f"=== Session Report ===\n"
            report += f"Session ID: {session_id}\n"
            report += f"User: {username}\n"
            report += f"Start Time: {start_time}\n"
            report += f"End Time: {end_time or 'Still active'}\n"
            report += f"Total Keypresses: {total_keypresses}\n"
            
            if common_keys:
                report += f"\nMost Common Keys:\n"
                for key, count in common_keys:
                    report += f"- {key}: {count} times\n"
                    
            return report
            
        except mysql.connector.Error as err:
            print(f"Generate report error: {err}")
            return f"Error generating report: {err}"


def main_menu():
    """Display main menu and handle user choices"""
    tracker = KeyboardTracker()
    current_user_id = None
    current_username = None
    
    while True:
        print("\n===== Keyboard Tracker with Authentication =====")
        print("1. Register a new user")
        print("2. Login")
        print("3. Start keyboard tracking")
        print("4. View my tracking history")
        print("5. Generate session report")
        print("6. Exit")
        
        choice = input("Enter your choice (1-6): ")
        
        if choice == "1":
            username = input("Enter new username: ")
            password = getpass.getpass("Enter password: ")
            tracker.db.register_user(username, password)
            
        elif choice == "2":
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            user_id, username = tracker.db.authenticate_user(username, password)
            if user_id:
                current_user_id = user_id
                current_username = username
                print("Login successful. You can now start tracking or view history.")
            
        elif choice == "3":
            if current_user_id:
                tracker.start_recording(current_user_id, current_username)
            else:
                print("You must be logged in to start tracking.")
                
        elif choice == "4":
            if current_user_id:
                sessions = tracker.db.get_user_sessions(current_user_id)
                if sessions:
                    print("\n=== Your Tracking Sessions ===")
                    for i, (session_id, start_time, end_time, log_file) in enumerate(sessions):
                        end_str = end_time if end_time else "Still active"
                        print(f"{i+1}. Session ID: {session_id}, Started: {start_time}, Ended: {end_str}")
                        print(f"   Log file: {log_file}")
                    
                    session_choice = input("\nEnter session number to view details (or 0 to go back): ")
                    if session_choice.isdigit() and 0 < int(session_choice) <= len(sessions):
                        session_idx = int(session_choice) - 1
                        session_id = sessions[session_idx][0]
                        log_file = sessions[session_idx][3]
                        
                        print(f"\n=== Session {session_id} Data ===")
                        print(f"Log file: {log_file}")
                        
                        # Ask if user wants to see data from database or file
                        view_choice = input("View data from (1) Database or (2) File? ")
                        
                        if view_choice == "1":
                            data = tracker.db.get_session_data(session_id)
                            if data:
                                print("\n=== Tracked Data from Database ===")
                                for data_type, content, timestamp in data[:20]:  # Show first 20 entries
                                    print(f"{timestamp}: [{data_type}] {content}")
                                
                                if len(data) > 20:
                                    print(f"... and {len(data) - 20} more entries")
                            else:
                                print("No data found for this session in database.")
                                
                        elif view_choice == "2":
                            try:
                                if os.path.exists(log_file):
                                    with open(log_file, "r") as f:
                                        lines = f.readlines()
                                        print("\n=== Tracked Data from File ===")
                                        for line in lines[:20]:  # Show first 20 lines
                                            print(line.strip())
                                        
                                        if len(lines) > 20:
                                            print(f"... and {len(lines) - 20} more lines")
                                else:
                                    print(f"Log file not found: {log_file}")
                            except Exception as e:
                                print(f"Error reading log file: {e}")
                else:
                    print("You don't have any tracking sessions yet.")
            else:
                print("You must be logged in to view your history.")
                
        elif choice == "5":
            if current_user_id:
                sessions = tracker.db.get_user_sessions(current_user_id)
                if sessions:
                    print("\n=== Your Tracking Sessions ===")
                    for i, (session_id, start_time, end_time, log_file) in enumerate(sessions):
                        end_str = end_time if end_time else "Still active"
                        print(f"{i+1}. Session ID: {session_id}, Started: {start_time}, Ended: {end_str}")
                    
                    session_choice = input("\nEnter session number to generate report (or 0 to go back): ")
                    if session_choice.isdigit() and 0 < int(session_choice) <= len(sessions):
                        session_idx = int(session_choice) - 1
                        session_id = sessions[session_idx][0]
                        
                        report = tracker.db.generate_data_report(session_id)
                        print("\n" + report)
                else:
                    print("You don't have any tracking sessions yet.")
            else:
                print("You must be logged in to generate reports.")
                
        elif choice == "6":
            print("Exiting program...")
            tracker.db.close_connection()
            break
            
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main_menu()