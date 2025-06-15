from django.db import models
from django.utils.translation import gettext_lazy as _

# Create your models here.

class CurrencyChoices(models.TextChoices):
    UZS = 'UZS', _("Uzbek so'm")
    USD = 'USD', _("US Dollar")
    RUB = 'RUB', _("Russian Ruble")
    EURO = 'EURO', _("Euro")

class Account(models.Model):   
    user = models.ForeignKey('users.CustomUser', on_delete=models.CASCADE)
    type = models.CharField(max_length=150)
    currency_type = models.TextField(max_length=4, choices=CurrencyChoices.choices, default=CurrencyChoices.UZS)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    description = models.CharField(max_length=1024, blank=True, null=True)

    def __str__(self):
        return self.type


class IncomeIconChoices(models.TextChoices):
    SALARY = 'fas fa-wallet', 'Salary'
    BUSINESS = 'fas fa-briefcase', 'Business'
    INVESTMENT = 'fas fa-chart-line', 'Investment'
    GIFT = 'fas fa-gift', 'Gift'
    FREELANCE = 'fas fa-laptop-code', 'Freelance'
    RENTAL = 'fas fa-home', 'Rental Income'


class ExpenseIconChoices(models.TextChoices):
    FOOD = 'fas fa-utensils', 'Food'
    TRANSPORT = 'fas fa-bus', 'Transport'
    HEALTH = 'fas fa-heartbeat', 'Health'
    SHOPPING = 'fas fa-shopping-bag', 'Shopping'
    EDUCATION = 'fas fa-book', 'Education'
    ENTERTAINMENT = 'fas fa-film', 'Entertainment'
    BILLS = 'fas fa-file-invoice-dollar', 'Bills'


class IncomeCategory(models.Model):
    user = models.ForeignKey('users.CustomUser', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    icon = models.CharField(max_length=50, choices=IncomeIconChoices.choices, default=IncomeIconChoices.SALARY)

    def __str__(self):
        return self.name


class ExpenseCategory(models.Model):
    user = models.ForeignKey('users.CustomUser', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    icon = models.CharField(max_length=50, choices=ExpenseIconChoices.choices, default=ExpenseIconChoices.FOOD)

    def __str__(self):
        return self.name
    

class Income(models.Model):
    user = models.ForeignKey('users.CustomUser', on_delete=models.CASCADE)
    category = models.ForeignKey(IncomeCategory, on_delete=models.CASCADE)
    account_type = models.ForeignKey(Account, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    date = models.DateField()
    description = models.CharField(max_length=1024, blank=True, null=True)

    class Meta:
        ordering = ['-date']


class Expense(models.Model):
    user = models.ForeignKey('users.CustomUser', on_delete=models.CASCADE)
    category = models.ForeignKey(ExpenseCategory, on_delete=models.CASCADE)
    account_type = models.ForeignKey(Account, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    date = models.DateField()
    description = models.CharField(max_length=1024, blank=True, null=True)

    class Meta:
        ordering = ['-date']