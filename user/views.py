import traceback 
import os
import time 
import json
from traceback  import format_exc
from asgiref.sync import sync_to_async, async_to_sync
from pymongo import MongoClient
from bson import ObjectId
from django.core import signing
from django.http import JsonResponse
from django.utils.timezone import now, timedelta
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings
from .mqtt import mqtt_handler 
from .models import *
from django.contrib.auth import logout

SWITCHES_FILE_PATH = os.path.join(settings.BASE_DIR, 'switches.json')

# Helper function to read switches from the 
# SWITCHES_FILE_PATH = 'switches.json'

def read_switches():
    if not os.path.exists(SWITCHES_FILE_PATH):
        # Create an empty file with an empty list if it doesn't exist
        with open(SWITCHES_FILE_PATH, 'w') as file:
            file.write('[]')
    
    with open(SWITCHES_FILE_PATH, 'r') as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return []

def write_switches(switches):
    with open(SWITCHES_FILE_PATH, 'w') as file:
        json.dump(switches, file, indent=4)
        
# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['Another_Db']
user_collection_register = db['user_register']
@csrf_exempt
def register_user(request):
    return async_to_sync(async_register_user)(request)

# Asynchronous handler
async def async_register_user(request):
    try:
        # Validate request method
        if request.method != 'POST':
            return JsonResponse({'error': 'Invalid request method'}, status=405)

        # Validate request body
        if not request.body:
            return JsonResponse({'error': 'Empty request body'}, status=400)

        # Parse the JSON body
        try:
            body = request.body.decode()
            data = json.loads(body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload'}, status=400)

        # Extract data
        user_name = data.get('user_name')
        email = data.get('email')
        password = data.get('password')

        # Validate input fields
        if not user_name or not email or not password:
            return JsonResponse({'error': 'Missing required fields'}, status=400)

        # Check if email already exists
        existing_user = await sync_to_async(user_collection_register.find_one)({'email': email})
        if existing_user:
            return JsonResponse({'error': 'Email already exists'}, status=400)

        # Hash the password
        hashed_password = make_password(password)

        # Prepare user data for insertion
        user_data = {
            'user_name': user_name,
            'email': email,
            'password': hashed_password,
        }

        # Insert user data into MongoDB
        result = await sync_to_async(user_collection_register.insert_one)(user_data)

        # Log and return a success response
        print(f"User saved with ID: {result.inserted_id}")
        return JsonResponse({'message': 'Registration successful!',}, status=201)

    except Exception as e:
        # Log the error and return an error response
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

@csrf_exempt
def login_user(request):
    return async_to_sync(async_login_user)(request)

# Asynchronous handler
async def async_login_user(request):
    try:
        # Validate request method
        if request.method != 'POST':
            return JsonResponse({'error': 'Invalid request method'}, status=405)

        # Validate request body
        if not request.body:
            return JsonResponse({'error': 'Empty request body'}, status=400)

        # Parse the JSON body
        try:
            body = request.body.decode()
            data = json.loads(body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload'}, status=400)

        # Extract email and password
        email = data.get('email')
        password = data.get('password')

        # Validate input fields
        if not email or not password:
            return JsonResponse({'error': 'Email and password are required'}, status=400)

        # Generate custom CSRF token
        def generate_custom_csrf_token(user_id, expires_in_days=365):
            expiration_date = (now() + timedelta(days=expires_in_days)).timestamp()
            token_data = {'user_id': user_id, 'exp': expiration_date}
            return signing.dumps(token_data, salt='custom-csrf-token')

        # Fetch user from database asynchronously
        try:
            user = await sync_to_async(register.objects.get)(email=email)
        except register.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Invalid email or password.'}, status=400)

        # Verify the password
        if not check_password(password, user.password):
            return JsonResponse({'success': False, 'message': 'Invalid email or password.'}, status=400)

        # Generate CSRF token
        csrf_token = generate_custom_csrf_token(str(user._id), expires_in_days=365)

        # Return success response
        return JsonResponse({
            'success': True,
            'message': 'Login successful!',
            'csrfToken': csrf_token  # Include CSRF token in response
        }, status=200)

    except Exception as e:
        # Log full traceback for debugging
        print("Unexpected error:", str(e))
        print("Full traceback:", format_exc())
        return JsonResponse({'error': 'Internal server error', 'details': str(e)}, status=500)


## use switch case ,asging ,hold try catch#
@csrf_exempt
def compare_token(request):
    if request.method == "GET":
        try:
            # Get Authorization Header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer'):
                return JsonResponse({'error': 'Authorization token is missing or invalid'}, status=401)

            # Extract token
            token = auth_header.split(' ')[1]
            print(f"Received Token: {token}")  # Log the received token

            # Decode Token
            def decode_token(token):
                try:
                    data = signing.loads(token, salt='custom-csrf-token')
                    print(f"Decoded Token Data: {data}")  # Log decoded data
                    return data
                except signing.BadSignature as e:
                    print(f"Bad Signature: {e}")  # Log error
                    return None

            token_data = decode_token(token)
            if not token_data:
                return JsonResponse({'error': 'Invalid token'}, status=401)

            # Extract and validate token details
            object_id = token_data.get('user_id')
            expiry_date = token_data.get('exp')
            if expiry_date and expiry_date < time.time():
                return JsonResponse({'error': 'Token has expired'}, status=401)

            if not object_id:
                return JsonResponse({'error': 'Invalid token data, user_id missing'}, status=401)

            # Check user existence
            try:
                user = register.objects.get(_id=ObjectId(object_id))
            except register.DoesNotExist:
                return JsonResponse({'error': 'User not found'}, status=404)

            # Return success response
            return JsonResponse({'message': 'Token is valid', 
                                'user': {'id': str(user._id), 
                                'username': user.user_name}})
        
        except Exception as e:
            print("Unexpected Error:", e)
            print("Traceback:", traceback.format_exc())
            return JsonResponse({'error': 'Internal server error'}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

# @csrf_exempt
def action_switch(request):
    return async_to_sync(async_action_switch)(request)

async def async_action_switch(request):
    try:
        # Validate request method
        if request.method != 'POST':
            return JsonResponse({'error': 'Invalid request method'}, status=405)

        # Validate request body
        if not request.body:
            return JsonResponse({'error': 'Empty request body'}, status=400)

        # Parse request body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload'}, status=400)

        # Extract data
        switchname = data.get('switchname')
        status = data.get('status', 'off')
        macaddress = data.get('macaddress')

        print(f"switname :{switchname},status: {status},macadress: {macaddress}")
        if not switchname or not macaddress :
            return JsonResponse({'error': 'Switchname or macaddress  are required'}, status=400)

        try:
            switchname_int = int(switchname)
            status_int = int(status)
        except ValueError:
            return JsonResponse({'error': 'Switchname and status must be integers'}, status=400)

        # Read existing switches
        switches = await sync_to_async(read_switches)()

        # Update switch status
        new_status = {'switchname': switchname_int, 'status': status_int, 'macaddress': macaddress}
        switches.append(new_status)
        await sync_to_async(write_switches)(switches)

        # Publish to MQTT
        try:
            # Use `sync_to_async` if `publish_switch_status` is synchronous
            await sync_to_async(mqtt_handler.publish_switch_status)(macaddress, switchname_int, status_int)
        except Exception as e:
            return JsonResponse({'error': f'Failed to publish to MQTT: {str(e)}'}, status=500)

        # Return success response
        return JsonResponse({'message': 'Switch status updated successfully', 'switch': new_status}, status=200)

    except Exception as e:
        return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)


def verify_csrf_token(csrf_token):
    """
    Verify the CSRF token (assumed to be a MongoDB ObjectId).
    Returns True if valid, False otherwise.
    """
    try:
        # Validate the token as a MongoDB ObjectId
        user_id = ObjectId(csrf_token)
        # Optionally, check this ObjectId against your user/session store in the DB
        # Example: users_collection.find_one({"_id": user_id})
        return user_id
    except Exception:
        return None

@csrf_exempt
def create_switch(request):
    if request.method == 'POST':
        # Retrieve CSRF token from headers
        csrf_token = request.headers.get('X-CSRFToken')
        if not csrf_token:
            return JsonResponse({'error': 'CSRF token missing'}, status=400)

        # Verify the CSRF token
        user_id = verify_csrf_token(csrf_token)
        if not user_id:
            return JsonResponse({'error': 'Invalid CSRF token'}, status=401)

        # Parse the request body
        if not request.body:
            return JsonResponse({'error': 'Empty request body'}, status=400)

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload'}, status=400)

        # Extract switchname from the request
        switchname = data.get('switchname')
        if not switchname:
            return JsonResponse({'error': 'Switch name is required'}, status=400)

        # Default switch_status to 0
        switch_status = 0

        # Read existing switches (mock logic)
        switches = read_switches()

        # Check if switch already exists (optional validation)
        for switch in switches:
            if switch['switchname'] == switchname:
                return JsonResponse({'error': 'Switch already exists'}, status=400)

        obj=Switch(switchname=switchname,status=switch_status,user_id=str(user_id))
        obj.save()
        # Create the new switch
        new_switch = {
            'switchname': switchname,
            'status': switch_status,
            'user_id': str(user_id) # Associate the switch with the user
        }
        switches.append(new_switch)
        write_switches(switches)

        return JsonResponse({'message': 'Switch created successfully', 'switch': new_switch}, status=200)
    return JsonResponse({'error': 'Invalid request method'}, status=405)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client['Another_Db']
users_collection = db['user_switch']
def get_data(request):
    if request.method == "POST":
        if not request.body:
            return JsonResponse({'error': 'Empty request body'}, status=400)
        
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError as e:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        user_id = data.get('user_id')
        
        if not user_id:
            return JsonResponse({'error': 'user_id is required'}, status=400)
        
        # Query MongoDB for all documents matching the user_id
        switches = list(users_collection.find({"user_id": user_id}))
        
        if not switches:
            return JsonResponse({'success': False, 'message': 'No switches found for this user_id.'}, status=404)
        
        # Format the result to remove ObjectId and prepare a clean response
        response_data = []
        for switch in switches:
            switch['_id'] = str(switch['_id'])# Convert ObjectId to string
            response_data.append(switch)
        
        return JsonResponse({
            'success': True,
            'data': response_data
        }, status=200)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

    
# @csrf_exempt
def read_switch(request, switchname=None):
    if request.method == 'GET':
        status = request.GET.get('status')  # Retrieve the desired status from query parameters
        
        # Read switches from storage
        switches = read_switches()
        
        if switchname:
            # Filter switches by switchname and status
            filtered_switches = [switch for switch in switches if switch['switchname'] == switchname]
            
            if status:
                filtered_switches = [switch for switch in filtered_switches if switch['status'] == status]
            
            if not filtered_switches:
                return JsonResponse({'error': 'Switch or status not found'}, status=404)
            
            # Optionally, get the most recent status or any specific logic
            latest_status = filtered_switches[-1]  # Get the most recent status

            try:
                # Optionally publish and subscribe to MQTT for the latest status
                mqtt_handler.publish_switch_status(switchname, latest_status['status'])
                
                response_message = mqtt_handler.subscribe_with_timeout(switchname, timeout=5)
                if response_message:
                    return JsonResponse({'switch': latest_status, 'mqtt_message': response_message}, status=200)
                else:
                    return JsonResponse({'switch': latest_status, 'mqtt_message': 'No response received via MQTT'}, status=200)
            except Exception as e:
                return JsonResponse({'error': f'Failed to communicate with MQTT: {str(e)}'}, status=500)
        else:
            # If no specific switchname is provided, return all switches
            return JsonResponse({'switches': switches}, status=200)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

client = MongoClient("mongodb://localhost:27017/")
db = client['your_database_name']
wifi_collection = db['wifi_credentials']
def save_wifi_credential(request):
    if request.method == 'POST':
        if not request.body:
            return JsonResponse({'error': 'Empty request body'}, status=400)
                
        # Log content type and raw body
        print(f"Content-Type: {request.content_type}")
        print(f"Raw Body: {request.body}")
        
        if request.content_type != 'application/json':
            return JsonResponse({'error': 'Invalid Content-Type. Expected application/json'}, status=400)

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError as e:
            print(f"JSON Decode Error: {str(e)}")
            return JsonResponse({'error': 'Invalid JSON payload'}, status=400)


        macaddress = data.get('macaddress')
        user_id = data.get('user_id')
        wifi_name = data.get('wifi_name')
        wifi_password = data.get('wifi_password')

        if not all([macaddress, user_id, wifi_name, wifi_password]):
            return JsonResponse({'error': 'All fields are required'}, status=400)

        try:
            # Using Djongo ORM
            credential, created = WiFiCredential.objects.get_or_create(
                macaddress=macaddress,
                defaults={
                    'user_id': user_id,
                    'wifi_name': wifi_name,
                    'wifi_password': wifi_password,
                }
            )
            if not created:
                credential.user_id = user_id
                credential.wifi_name = wifi_name
                credential.wifi_password = wifi_password
                credential.save()
            
            # Publish WiFi data
            mqtt_handler.mqtt_publish_wifi_data(macaddress, wifi_name, wifi_password)
            return JsonResponse({'message': 'WiFi credentials saved and published successfully'}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'Failed to save WiFi credentials: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

# @csrf_exempt
def update_switch(request):
    if request.method == "PUT":
        # Retrieve `user_id` and `switch_id` from query parameters
        user_id = request.GET.get('user_id')
        switch_id = request.GET.get('switch_id')

        if not user_id or not switch_id:
            return JsonResponse({'error': 'user_id or switch_id required'}, status=400)

        # Validate `switch_id` as ObjectId
        try:
            switch_id = ObjectId(switch_id)  # Convert switch_id to ObjectId
        except Exception:
            return JsonResponse({'error': 'Invalid switch_id format'}, status=400)

        # Parse the request body for `switchname`
        # try:
        #     data = json.loads(request.body)
        # except json.JSONDecodeError:
        #     return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)

        # new_switchname = data.get('switchname')
        new_switchname = request.GET.get('switchname')
        if not new_switchname:
            return JsonResponse({'error': 'switchname is required in the request body'}, status=400)

        # Perform the update in MongoDB
        result = collection.update_one(
            {"user_id": user_id, "_id": switch_id},
            {"$set": {"switchname": new_switchname}}
        )

        # Check the result of the update operation
        if result.matched_count > 0:
            return JsonResponse({'success': True, 'message': 'Switchname updated successfully.'}, status=200)
        else:
            return JsonResponse({'success': False, 'message': 'No matching document found for the given user_id and switch_id.'}, status=404)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)


# Initialize MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client['Another_Db']
collection = db['user_switch']

def delete_switch(request):
    if request.method == "DELETE":
        
        user_id = request.GET.get('user_id')
        switch_id = request.GET.get('switch_id')

        if not user_id or not switch_id:
            return JsonResponse({'error': 'user_id or switch_id required'}, status=400)
        
        # Ensure switch_id is a valid ObjectId
        try:
            switch_id = ObjectId(switch_id)  # Convert switch_id to ObjectId
        except Exception as e:
            return JsonResponse({'error': 'Invalid switch_id format'}, status=400)

        # Query MongoDB to find the switch by user_id and switch_id
        switch = collection.find_one({"user_id": user_id, "_id": switch_id})

        if not switch:
            return JsonResponse({'success': False, 'message': 'No switch found for the given user_id and switch_id.'}, status=404)
        
        # Delete the switch from the database
        result = collection.delete_one({"user_id": user_id, "_id": switch_id})

        if result.deleted_count > 0:
            return JsonResponse({'success': True, 'message': 'Switch deleted successfully.'}, status=200)
        else:
            return JsonResponse({'success': False, 'message': 'Failed to delete the switch.'}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def logout_user(request):
    return async_to_sync(async_logout_user)(request)

async def async_logout_user(request):
    try:
        # Validate request method
        if request.method != 'POST':
            return JsonResponse({'error': 'Invalid request method'}, status=405)

        # Perform logout operation
        await sync_to_async(logout)(request)

        # Return success response
        return JsonResponse({'message': 'Logout successful!'}, status=200)

    except Exception as e:
        # Log the error for debugging
        import traceback
        print("Unexpected error:", str(e))
        print("Full traceback:", traceback.format_exc())
        return JsonResponse({'error': 'Internal server error', 'details': str(e)}, status=500)

# New API to list all switches and their statuses
# @csrf_exempt
def list_all_switches(request):
    if request.method == 'GET':
        switches = read_switches()
        return JsonResponse({'switches': switches}, status=200)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

# @csrf_exempt
def gethomeappliancesfrontend(request):
    
    try:
        mqtt_message = mqtt_handler.received_message  # Get the latest MQTT message

        if mqtt_message == "I am ready":
            # Send response message to ESP32
            mqtt_handler.send_response_message("hi")
            
            response_data = {
                'success': True,
                
                'mqtt_message': mqtt_message  # Send the MQTT message to the frontend
            }
        else:
            response_data = {
                'success': False,
                
            }

        return JsonResponse(response_data)
    except Exception as e:
        error_response = {
            'success': False,
            'message': str(e)
        }
        return JsonResponse(error_response, status=500)
    
    
