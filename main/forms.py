from django import forms
from .models import Account, IncomeCategory, ExpenseCategory, Income, Expense

class AccountForm(forms.ModelForm):
    class Meta:
        model = Account
        fields = ['type', 'currency_type', 'amount', 'description']


class IncomeCategoryForm(forms.ModelForm):
    class Meta:
        model = IncomeCategory
        fields = ['name', 'icon']
        widgets = {
            'icon': forms.Select(attrs={'class': 'form-control icon-select'}),
        }


class ExpenseCategoryForm(forms.ModelForm):
    class Meta:
        model = ExpenseCategory
        fields = ['name', 'icon']
        widgets = {
            'icon': forms.Select(attrs={'class': 'form-control icon-select'}),
        }

    
class IncomeForm(forms.ModelForm):
    class Meta:
        model = Income
        fields = ['category', 'account_type', 'amount', 'date', 'description']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
        }


class ExpenseForm(forms.ModelForm):
    class Meta:
        model = Expense
        fields = ['category', 'account_type', 'amount', 'date', 'description']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
        }