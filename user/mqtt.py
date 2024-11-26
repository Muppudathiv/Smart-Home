import paho.mqtt.client as mqtt
import json
import logging
import time
import threading

# MQTT settings
broker_address = "194.238.18.221"
port = 1883
live_topic = "Live"
username = "grafin@1234"
password = "grafin@1234"

class MQTTHandler:
    def __init__(self):
        self.client = mqtt.Client()
        self.client.username_pw_set(username, password)
        
        # Set MQTT client callbacks
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect

        self.connected = False
        self.received_message = None
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.DEBUG)
        self.delay = 5  # Initial delay for reconnection
        self.connect()

    def connect(self):
        try:
            self.logger.info("Connecting to MQTT broker...")
            self.client.connect(broker_address, port, 60)
            self.client.loop_start()
        except Exception as e:
            self.logger.error(f"Failed to connect to MQTT broker: {str(e)}")
            self.schedule_reconnect()

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.logger.info('Connected to MQTT broker')
            self.connected = True

            # Subscribe to acknowledgment topic
            self.client.subscribe("ACKNOWLEDGMENT")
            self.logger.info("Subscribed to 'ACKNOWLEDGMENT' topic")
        elif rc == 5:
            self.logger.error('Authentication failed - not authorized')
        else:
            self.logger.error(f'Failed to connect with result code {rc}')
            self.connected = False
            self.schedule_reconnect()

    def on_message(self, client, userdata, msg):
        try:
            topic = msg.topic
            payload = msg.payload.decode()
            self.logger.info(f"Received message on topic '{topic}': {payload}")

            # Check if it's the acknowledgment message
            if topic == "ACKNOWLEDGMENT":
                print(f"Acknowledgment received: {payload}")
                self.logger.info(f"Acknowledgment received: {payload}")
            else:
                # Handle other messages
                self.handle_message(payload)
        except Exception as e:
            self.logger.error(f"Error in on_message: {str(e)}")

    def handle_message(self, message):
        try:
            # Attempt to parse message as JSON
            message_data = json.loads(message)
            if 'status' in message_data and 'switchname' in message_data:
                self.logger.info(f"Status received: {message_data['status']}, Switchname: {message_data['switchname']}")
        except json.JSONDecodeError:
            # Handle as comma-separated values if not JSON
            self.logger.error("Failed to parse message as JSON. Trying as comma-separated format.")
            try:
                switchname, status = map(int, message.split(','))
                self.logger.info(f"Status received: {status}, Switchname: {switchname}")
            except ValueError:
                self.logger.error("Failed to parse message as comma-separated format.")
            except Exception as e:
                self.logger.error(f"Error handling message: {e}")

    def on_disconnect(self, client, userdata, rc):
        self.logger.warning("Client got disconnected with code %s", rc)
        self.connected = False
        if rc != 0:
            self.schedule_reconnect()

    def schedule_reconnect(self, delay=None):
        if delay is None:
            delay = self.delay
        self.logger.info(f"Reconnecting in {delay} seconds...")
        time.sleep(delay)
        self.reconnect()

    def reconnect(self):
        while not self.connected:
            try:
                self.logger.info("Attempting to reconnect to MQTT broker")
                self.client.reconnect()
                self.connected = True
                self.logger.info("Reconnected to MQTT broker")
            except Exception as e:
                self.logger.error(f"Reconnection failed: {str(e)}")
                self.delay = min(60, self.delay * 2)  # Exponential backoff for reconnection
                self.schedule_reconnect()

    def subscribe_to_acknowledgments(self, macaddress):
        topic = f"{macaddress}/ack"
        self.client.subscribe(topic)
        self.logger.info(f"Subscribed to acknowledgment topic '{topic}'")

    def subscribe_with_timeout(self, topic, timeout=5):
        self.received_message = {}
        self.client.subscribe(topic)

        start_time = time.time()
        while not self.received_message and time.time() - start_time < timeout:
            time.sleep(1)
            self.logger.debug(f"Waiting for message on topic '{topic}'")

        self.logger.info(f"Subscribed to topic '{topic}': {self.received_message}")
        return self.received_message

    def publish(self, topic, payload):
        # Publish a plain payload to the specified topic
        self.client.publish(topic, payload)
        self.logger.info(f"Published to topic '{topic}': {payload}")
        
    ################## ORINAL CODE FOR HTTP ITS RUN BY ACTION SWITCH 
    def publish_switch_status(self, macaddress, switchname, status):
        print(f"macaddressfromviiew '{macaddress}'")
        payload = f"{int(switchname)},{int(status)}"
        topic = f"{macaddress}" 
        self.publish(topic, payload)
    
    ################## MODIFY CODE FOR WEB SOCKET BY CONSUMERS.PY ANS ASGI.PY        

    def publish_switch_status_websocket(self, macaddress, switchname, status):
            if not self.connected:
                print("MQTT client is not connected.")
                return

            # Ensure macaddress is not None or invalid
            if not macaddress:
                print("Error: 'macaddress' is required but was not provided.")
                return

            try:
                payload = f"{switchname},{status}"
                default_topic = f"{macaddress}"  # Replace with your default topic
                print(f"Publishing via WebSocket -> Topic: {default_topic}, macaddress: {macaddress}, Payload: {payload}")
                self.publish(default_topic, payload)
            except Exception as e:
                print(f"Error during MQTT publish: {str(e)}")
                
    def mqtt_publish_wifi_data(self, macaddress, wifi_name, wifi_password):
        topic = f"{macaddress}/wifi"
        payload = f"{wifi_name},{wifi_password}"  # Combine as a plain string separated by a comma
        try:
            mqtt_handler.publish(topic, payload)
        except Exception as e:
            raise Exception(f"Failed to publish MQTT data: {str(e)}")



# Initialize MQTT handler
mqtt_handler = MQTTHandler()

# Start the MQTT loop
def start_mqtt_loop():
    try:
        while True:
            if mqtt_handler.connected:
                time.sleep(10)
    except KeyboardInterrupt:
        mqtt_handler.logger.info("MQTT loop stopped cleanly")

mqtt_thread = threading.Thread(target=start_mqtt_loop)
mqtt_thread.daemon = True
mqtt_thread.start()

    # def publish_switch_status(self, macaddress, switchname, status):
    #         print(f"macaddressfromviiew '{macaddress}'")
    #     # Convert to comma-separated integer format and use macaddress as the topic
    #         payload = f"{int(switchname)},{int(status)}"
    #         topic = f"{macaddress}"
            
    #         # Dynamically using macaddress as part of the topic
    #         self.publish(topic, payload)