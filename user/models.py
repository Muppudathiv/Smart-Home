from django.db import models
from djongo import models

class register(models.Model):
    _id = models.ObjectIdField(primary_key=True)
    user_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)  # Ensure uniqueness
    password = models.CharField(max_length=200)

    def __str__(self):
        return self.user_name

class Switch(models.Model):
    # _id = models.ObjectIdField(primary_key=True)
    switchname = models.CharField(max_length=255, unique=True)  # Ensure switch names are unique
    status = models.IntegerField(default=0)  # Default status is 0
    user_id = models.CharField(max_length=24)  # Store user_id as a string representation of MongoDB ObjectId

class WiFiCredential(models.Model):
    macaddress = models.CharField(max_length=255, unique=True)
    user_id = models.CharField(max_length=24)  # This should match the MongoDB ObjectId format
    wifi_name = models.CharField(max_length=255)
    wifi_password = models.CharField(max_length=255)

    def __str__(self):
        return self.macaddress
