import os
import json
from channels.generic.websocket import WebsocketConsumer
from .mqtt import mqtt_handler 

# Function to read switches from the JSON file
SWITCHES_FILE_PATH = "switches.json"

# Function to read switches from a JSON file
def read_switches():
    if not os.path.exists(SWITCHES_FILE_PATH):
        # Create an empty file with an empty list if it doesn't exist
        with open(SWITCHES_FILE_PATH, 'w') as file:
            file.write('[]')
    
    # Attempt to read and parse the JSON data
    try:
        with open(SWITCHES_FILE_PATH, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError:
        print("JSON decode error: The file might be empty or corrupted.")
        return []  # Return an empty list if JSON is invalid
    except Exception as e:
        print(f"Unexpected error reading switches: {e}")
        return []

# Function to write switches to the JSON file
def write_switches(switches):
    try:
        with open(SWITCHES_FILE_PATH, 'w') as file:
            json.dump(switches, file, indent=4)
    except Exception as e:
        print(f"Error writing to file: {e}")
        
class SwitchConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()
        print("WebSocket connection accepted.")

    def disconnect(self, close_code):
        print(f"WebSocket disconnected. Close code: {close_code}")

    def receive(self, text_data):
        try:
            # Parse incoming JSON data
            data = json.loads(text_data)
        except json.JSONDecodeError:
            error_message = {'error': 'Invalid JSON payload'}
            self.send(text_data=json.dumps(error_message))
            print("Received invalid JSON payload.")
            return

        # Extract and validate data
        switchname = data.get('switchname')
        status = data.get('status', 0)
        macaddress = data.get('macaddress')

        if not switchname or not macaddress:
            error_message = {'error': 'Switchname and macaddress are required'}
            self.send(text_data=json.dumps(error_message))
            return

        # Proceed with the update
        try:
            # Call publish method without the topic
            mqtt_handler.publish_switch_status_websocket(macaddress, switchname, status)
            success_message = {'message': 'Request processed, waiting for device acknowledgment'}
            self.send(text_data=json.dumps(success_message))
        except Exception as e:
            error_message = {'error': f'Failed to publish to MQTT: {str(e)}'}
            self.send(text_data=json.dumps(error_message))

    def send_acknowledgment(self, switchname, status, macaddress):
        """
        Method to send acknowledgment back to the WebSocket client.
        """
        acknowledgment_message = {
            'message': 'Switch status updated and acknowledged by device',
            'switchname': switchname,
            'status': status,
            'macaddress': macaddress
        }
        self.send(text_data=json.dumps(acknowledgment_message))
        print(f"Acknowledgment sent to WebSocket: {acknowledgment_message}")









