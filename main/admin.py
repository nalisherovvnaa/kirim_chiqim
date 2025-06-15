from django.contrib import admin
from .models import (
    Account, IncomeCategory, ExpenseCategory,
    Income, Expense
)

@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'type', 'currency_type', 'amount', 'description')
    list_filter = ('currency_type',)


@admin.register(IncomeCategory)
class IncomeCategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'name', 'icon')


@admin.register(ExpenseCategory)
class ExpenseCategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'name', 'icon')


@admin.register(Income)
class IncomeAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'category', 'account_type', 'amount', 'date', 'description')
    list_filter = ('date', 'category')
    date_hierarchy = 'date'

@admin.register(Expense)
class ExpenseAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'category', 'account_type', 'amount', 'date', 'description')
    list_filter = ('date', 'category')
    date_hierarchy = 'date'
