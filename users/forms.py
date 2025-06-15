from django import forms
from .models import CustomUser
from services import is_valid_email, is_valid_phone


class UserRegistrationForm(forms.ModelForm):
    confirm_password = forms.CharField(widget=forms.PasswordInput, required=True, label="Confirm Password")

    class Meta:
        model = CustomUser
        fields = ['username', 'address', 'password']
        widgets = {
            'password': forms.PasswordInput()
        }
       
    def clean(self):
        cleaned_data = super().clean()
        address = cleaned_data.get('address')
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if not address:
            raise forms.ValidationError('Address is requeired. Enter phone number or email.')

        if not is_valid_phone(address) and not is_valid_email(address):
            raise forms.ValidationError('Invalid phone number or email, phone number do not start with `+`')

        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data


    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        if commit:
            user.save()
        return user


class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'address', 'avatar']
    
class AvatarUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['avatar']

class ChangePasswordForm(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput)
    new_password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    def __init__(self, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean(self):
        cleaned_data = super().clean()
        old_password = cleaned_data.get('old_password')
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if not old_password:
            raise forms.ValidationError("You must enter old password.")

        if not self.user.check_password(old_password):
            raise forms.ValidationError("Old password is incorrect.")

        if new_password and confirm_password and new_password != confirm_password:
            raise forms.ValidationError("New passwords do not match.")
        
        return cleaned_data