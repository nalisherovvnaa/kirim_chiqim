from rest_framework import serializers
from users.models import CustomUser
from main.models import CurrencyChoices

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = '__all__'


class CustomUserUpdateSerializer(serializers.ModelSerializer):
    currency = serializers.ChoiceField(choices=CurrencyChoices.choices)

    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'username', 'address', 'avatar', 'currency']
