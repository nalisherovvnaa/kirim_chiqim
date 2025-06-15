from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
from main.models import CurrencyChoices

# Create your models here.

class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError("Username is required")
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(username, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    username = models.CharField(max_length=100, unique=True)
    address = models.CharField(max_length=150, unique=True)
    avatar = models.ImageField(upload_to='avatars/', default='avatars/default.png')
    currency = models.TextField(max_length=4, choices=CurrencyChoices.choices, default=CurrencyChoices.UZS)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'username'

    objects = CustomUserManager()

    def __str__(self):
        return self.username

    @property
    def format(self):
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'username': self.username,
            'address': self.address,
            'avatar': self.avatar.url,
            'currency': self.currency
            }


class OTP(models.Model):
    address = models.CharField(max_length=150)
    key = models.CharField(max_length=150)
    is_expired = models.BooleanField(default=False)
    is_used = models.BooleanField(default=False)
    tried = models.IntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if self.tried >= 3:
            self.is_expired = True
        super(OTP, self).save()

    def check_expired(self):
        expire_time = self.created + timezone.timedelta(minutes=5)
        if timezone.now() > expire_time:
            self.is_expired = True
            self.save()
        return self.is_expired