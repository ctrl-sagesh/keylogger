import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import io
from datetime import datetime
import mysql.connector

# Import the classes to test
from cli import KeyboardTracker, DatabaseHandler

class SimplifiedTests(unittest.TestCase):
    """Simplified tests for KeyboardTracker with just 3 main features"""
    
    @patch('mysql.connector.connect')
    def test_database_connection(self, mock_connect):
        """Test 1: Database connection functionality"""
        # Configure the mock
        mock_cursor = MagicMock()
        mock_connect.return_value.cursor.return_value = mock_cursor
        
        # Create an instance of DatabaseHandler
        db_handler = DatabaseHandler()
        
        # Verify the connection was attempted with correct parameters
        mock_connect.assert_called_with(
            host="localhost",
            user="root",
            password=""
        )
        
        # Just verify database was created, don't check exact number of calls
        mock_cursor.execute.assert_any_call(f"CREATE DATABASE IF NOT EXISTS {db_handler.database}")
        
        print("Test 1 done OK")
    
    @patch('mysql.connector.connect')
    def test_user_authentication(self, mock_connect):
        """Test 2: User authentication functionality"""
        # Configure the mock
        mock_cursor = MagicMock()
        mock_connect.return_value.cursor.return_value = mock_cursor
        
        # For successful authentication
        mock_cursor.fetchone.return_value = (1,)  # Return user_id
        
        # Create an instance of DatabaseHandler
        db_handler = DatabaseHandler()
        
        # Reset mock calls
        mock_cursor.reset_mock()
        
        # Test successful authentication
        user_id, username = db_handler.authenticate_user("testuser", "testpassword")
        
        # Verify user_id was returned correctly
        self.assertEqual(user_id, 1)
        self.assertEqual(username, "testuser")
        
        # For unsuccessful authentication
        mock_cursor.fetchone.return_value = None  # No user found
        
        # Test unsuccessful authentication
        user_id, username = db_handler.authenticate_user("testuser", "wrongpassword")
        
        # Verify user_id is None for failed authentication
        self.assertIsNone(user_id)
        self.assertIsNone(username)
        
        print("Test 2 done OK")
    
    def test_recording_functionality(self):
        """Test 3: Recording functionality"""
        # Create a custom mock for KeyboardTracker to test the recording logic
        # without actually hooking into keyboard events
        
        # First create our mocks
        mock_db = MagicMock()
        mock_db.create_session.return_value = 123
        
        # Create the instance and replace its db with our mock
        with patch('builtins.open', unittest.mock.mock_open()):
            tracker = KeyboardTracker()
            tracker.db = mock_db
            
            # Mock these methods to avoid actual keyboard hooking
            tracker.start_recording = MagicMock()
            tracker.stop_recording = MagicMock()
            
            # Test the basic recording workflow
            # 1. Set up a recording session
            tracker.current_user_id = 1
            tracker.recording = True
            tracker.session_id = 123
            tracker.tracking_data = [("a", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))]
            
            # 2. Simulate a key press
            mock_event = MagicMock()
            mock_event.name = "b"
            
            # Manually call the event handler method
            with patch('builtins.open', unittest.mock.mock_open()):
                # Create user log files entry
                tracker.user_log_files = {1: "test_log.txt"}
                
                # Test on_key_event method directly
                tracker.on_key_event(mock_event)
                
                # Verify tracking data was updated
                self.assertEqual(len(tracker.tracking_data), 2)  # Original "a" + new "b"
                self.assertEqual(tracker.tracking_data[1][0], "b")
            
            # 3. Simulate storing data to database when enough keys are collected
            tracker.tracking_data = [("a", datetime.now().strftime("%Y-%m-%d %H:%M:%S")) for _ in range(50)]
            
            # Use a fresh mock for this specific test
            fresh_mock_db = MagicMock()
            tracker.db = fresh_mock_db
            tracker.session_id = 456
            
            with patch('builtins.open', unittest.mock.mock_open()):
                # Call on_key_event which should trigger batch saving
                mock_event.name = "z"
                tracker.on_key_event(mock_event)
                
                # Verify store_tracking_data was called
                fresh_mock_db.store_tracking_data.assert_called_once()
        
        print("Test 3 done OK")


if __name__ == "__main__":
    unittest.main()