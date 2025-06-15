from users.models import CustomUser
from config import settings
from django.core.mail import send_mail
import re
import requests

# O‘zbekiston telefon raqamlari uchun regex (998 bilan boshlanadi)
REGEX_PHONE = r"^998([235789]{2}|(9[013-57-9]))\d{7}$"

# Email uchun regex
REGEX_EMAIL = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

# Telefon raqamini tekshiruvchi funksiya
def is_valid_phone(phone: str) -> bool:
    return re.match(REGEX_PHONE, phone) is not None

# Emailni tekshiruvchi funksiya
def is_valid_email(email: str) -> bool:
    return re.match(REGEX_EMAIL, email) is not None

def send_code(code, address):
    if isinstance(address, str):
        addresses = [address]

    subject = 'Code for reset password'
    from_email = settings.EMAIL_HOST_USER
    for address in addresses:
        if is_valid_email(address):
            send_mail(subject, code, from_email, [address])
        elif is_valid_phone(address):
            print(f"{code} is sended to {address}")
        else:
            print('Invalid address')


def get_currency():
    response = requests.get('https://cbu.uz/oz/arkhiv-kursov-valyut/json/')
    data = response.json()
    lst = []
    for i, currency in enumerate(data):
        lst.append(currency)
        if i == 2:
            break
    return lst