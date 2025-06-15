from django.shortcuts import render, redirect
from django.views import View
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import authenticate, login, logout
from .forms import UserRegistrationForm, ChangePasswordForm, ProfileUpdateForm, AvatarUpdateForm
from .models import CustomUser, OTP
from  main.models import Account, Income, Expense
from django.contrib.auth import update_session_auth_hash
from services import send_code
import random
import uuid

# Create your views here.

class SignUpView(View):
    def get(self, request):
        form = UserRegistrationForm()
        return render(request, 'users/register.html', {'form': form})
    
    def post(self, request):
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            address = form.cleaned_data['address']
            code = f"{random.randint(100000, 999999)}"
            key = code[:3] + str(uuid.uuid4()) + code[3:]
            OTP.objects.create(address=address, key=key)
            send_code(code, address)

            request.session['form_data'] = form.cleaned_data
            request.session['reset_address'] = address
            return redirect('users:verify_code')
        return render(request, 'users/register.html', {'form': form})


class LoginView(View):
    def get(self, request):
        form = AuthenticationForm()
        return render(request, 'users/login.html', {'form': form})

    def post(self, request):
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('main:main')
            else:
                form.add_error(None, "Noto'g'ri username yoki parol.")
            return redirect('main:main')
        return render(request, 'users/login.html', {'form': form})
    

class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('users:login')


class ProfileView(LoginRequiredMixin, View):
    login_url = "users:login"

    def get(self, request):
        user = request.user
        incomes = Income.objects.filter(user=user)
        expenses = Expense.objects.filter(user=user)
        accounts = Account.objects.filter(user=user)
        total_balance = sum(account.amount for account in accounts)
        transactions_count = incomes.count() + expenses.count()

        context = {
            'total_balance': total_balance,
            'transactions_count': transactions_count,
        }
        return render(request, 'users/profile.html', context)


class ProfileUpdateView(LoginRequiredMixin, View):
    login_url = 'users:login'
    next = 'users:update_profile'

    def get(self, request):
        user = request.user
        form = ProfileUpdateForm(instance=user)
        return render(request, 'users/update_profile.html', {'form': form})
    
    def post(self, request):
        user = request.user
        form = ProfileUpdateForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            return redirect('users:profile')
        return render(request, 'users/update_profile.html', {'form': form})
    

class ChangePasswordView(LoginRequiredMixin, View):
    login_url = 'users:login'

    def get(self, request):
        form = ChangePasswordForm(user=request.user)
        return render(request, 'users/change_password.html', {'form': form})
    
    def post(self, request):
        form = ChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            user = request.user
            user.set_password(form.cleaned_data['new_password'])
            user.save()
            update_session_auth_hash(request, user)
            return redirect('users:profile')
        return render(request, 'users/change_password.html', {'form': form})
    

class ResetPasswordRequestView(View):
    def get(self, request):
        return render(request, 'users/reset_password.html')

    def post(self, request):
        address = request.POST.get('address')
        if not address:
            return render(request, 'users/reset_password.html', {'error': "Invalid phone number or email"})

        try:
            user = CustomUser.objects.get(address=address)
        except CustomUser.DoesNotExist:
            return render(request, 'users/reset_password.html', {'error': "Bunday foydalanuvchi yo'q"})

        code = f"{random.randint(100000, 999999)}"
        key = code[:3] + str(uuid.uuid4()) + code[3:]
        OTP.objects.create(address=address, key=key)
        send_code(code, address)

        request.session['reset_address'] = address
        return redirect('users:verify_code')  


class VerifyCodeView(View):
    def get(self, request):
        return render(request, 'users/verify_code.html')

    def post(self, request):
        address = request.session.get('reset_address')
        code_input = request.POST.get('code')
        form_data = request.session.get('form_data')  # bu dict kornishida

        try:
            user = CustomUser.objects.get(address=address)
            print(user.address)
        except CustomUser.DoesNotExist:
            if not form_data:
                return render(request, 'users/verify_code.html', {'error': "Ma'lumotlar topilmadi"})
            otp = OTP.objects.filter(address=address, is_used=False, is_expired=False).last()
            if not otp or otp.key[:3] + otp.key[-3:] != code_input:
                if otp:
                    otp.tried += 1
                    otp.save()
                return render(request, 'users/verify_code.html', {'error': "Kod noto'g'ri"})

            if otp.check_expired():
                return render(request, 'users/verify_code.html', {'error': 'Kod muddati tugagan'})

            otp.is_used = True
            otp.save()

            form = UserRegistrationForm(form_data)
            if form.is_valid():
                form.save()
                return redirect('users:login')
            else:
                return render(request, 'users/verify_code.html', {'error': 'Formani qayta tiklashda xatolik'})

        try:
            otp = OTP.objects.filter(address=address, is_used=False, is_expired=False).last()
            if not otp or otp.key[:3] + otp.key[-3:] != code_input:
                return render(request, 'users/verify_code.html', {'error': "Kod noto'g'ri"})
            
            if otp.check_expired():
                return render(request, 'users/verify_code.html', {'error': 'Kod muddati tugagan'})

            otp.is_used = True
            otp.save()
            request.session['reset_verified'] = True
            return redirect('users:set_new_password')
        except:
            return render(request, 'users/verify_code.html', {'error': 'Xatolik yuz berdi'})


class SetNewPasswordView(View):
    def get(self, request):
        if not request.session.get('reset_verified'):
            return redirect('users:reset_password')
        return render(request, 'users/set_new_password.html')

    def post(self, request):
        password = request.POST.get('password')
        confirm = request.POST.get('confirm_password')
        address = request.session.get('reset_address')
        if password != confirm:
            return render(request, 'users/set_new_password.html', {'error': 'Passwords do not match!'})

        try:
            user = CustomUser.objects.get(address=address)
        except CustomUser.DoesNotExist:
            return render(request, "users/reset_password.html", {"error": "Invalid user!"})

        user = CustomUser.objects.get(address=address)
        user.set_password(password)
        user.save()

        request.session.flush()

        return redirect('users:login')
