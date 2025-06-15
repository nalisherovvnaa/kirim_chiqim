from django.contrib import admin
from .models import CustomUser, OTP

# Register your models here.

class OTPAdmin(admin.ModelAdmin):
    list_display = ['id', 'address', 'key']

admin.site.register(CustomUser)
admin.site.register(OTP, OTPAdmin)