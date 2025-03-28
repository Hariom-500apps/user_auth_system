from rest_framework import serializers
from . import models

class UserProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.CustomUser
        fields =['username', 'email',"user_type"]