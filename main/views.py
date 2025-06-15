from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import Account, IncomeCategory, ExpenseCategory, Income, Expense
from .forms import AccountForm, IncomeCategoryForm, ExpenseCategoryForm, IncomeForm, ExpenseForm
from django.utils import timezone
from itertools import chain
from operator import attrgetter
from datetime import datetime, timedelta
from services import get_currency

# Create your views here.

class MainView(LoginRequiredMixin, View):  # Hammasi OK
    login_url = 'users:login'
    next = 'main:main'
    
    def get(self, request):
        now = timezone.now()
        incomes = Income.objects.filter(user=request.user, date__year=now.year, date__month=now.month)
        expenses = Expense.objects.filter(user=request.user, date__year=now.year, date__month=now.month)
        accounts = Account.objects.filter(user=request.user)
        total_income, total_expense, total_balance = 0, 0, 0
        for income in incomes:
            total_income += income.amount
        for expense in expenses:
            total_expense += expense.amount
        for account in accounts:
            total_balance += account.amount
        
        context = {
            'total_income': total_income,
            'total_expense': total_expense,
            'total_balance': total_balance,
        }
        return render(request, 'main/main.html', context)


class TransactionsView(LoginRequiredMixin, View): # Hammasi OK 
    login_url = 'users:login'
    next = 'main:transactions'

    def get(self, request):
        now = timezone.localtime(timezone.now())
        filt = request.GET.get('filter')
        start = request.GET.get('start')
        end = request.GET.get('end')

        accounts = Account.objects.filter(user=request.user)
        incomes = Income.objects.filter(user=request.user)
        expenses = Expense.objects.filter(user=request.user)

        if filt == 'day':
            incomes = incomes.filter(date=now.date())
            expenses = expenses.filter(date=now.date())

        elif filt == 'week':
            start_of_week = now.date() - timedelta(days=now.weekday())
            end_of_week = start_of_week + timedelta(days=7)
            incomes = incomes.filter(date__range=(start_of_week, end_of_week))
            expenses = expenses.filter(date__range=(start_of_week, end_of_week))

        elif filt == 'month':
            incomes = incomes.filter(date__year=now.year, date__month=now.month)
            expenses = expenses.filter(date__year=now.year, date__month=now.month)

        elif start or end:
            if not start:
                start = '0001-01-01'
            if not end:
                end = now.strftime('%Y-%m-%d')

            try:
                start_date = datetime.strptime(start, '%Y-%m-%d').date()
                end_date = datetime.strptime(end, '%Y-%m-%d').date()
                incomes = incomes.filter(date__range=(start_date, end_date))
                expenses = expenses.filter(date__range=(start_date, end_date))
            except ValueError:
                return render(request, 'main/transactions.html', {
                    'transactions': [],
                    'accounts': accounts,
                    'error': 'Invalid date format.'
                })

        for income in incomes:
            income.type = 'Income'
        for expense in expenses:
            expense.type = 'Expense'

        transactions = sorted(
            chain(incomes, expenses),
            key=attrgetter('date'),
            reverse=True
        )

        context = {
            'transactions': transactions,
            'accounts': accounts,
        }
        return render(request, 'main/transactions.html', context)
    

class IncomeView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:income'

    def get(self, request):
        now = timezone.localtime(timezone.now())
        filt = request.GET.get('filter')
        start = request.GET.get('start')
        end = request.GET.get('end')

        incomes = Income.objects.filter(user=request.user)
        total_income = sum(income.amount for income in incomes)
        this_month = sum(income.amount for income in incomes.filter(date__year=now.year, date__month=now.month))

        if filt == 'day':
            incomes = incomes.filter(date=now.date())

        elif filt == 'week':
            start_of_week = now.date() - timedelta(days=now.weekday())
            end_of_week = start_of_week + timedelta(days=7)
            incomes = incomes.filter(date__range=(start_of_week, end_of_week))

        elif filt == 'month':
            incomes = incomes.filter(date__year=now.year, date__month=now.month)

        elif start or end:
            if not start:
                start = '0001-01-01'
            if not end:
                end = now.strftime('%Y-%m-%d')

            try:
                start_date = datetime.strptime(start, '%Y-%m-%d').date()
                end_date = datetime.strptime(end, '%Y-%m-%d').date()
                incomes = incomes.filter(date__range=(start_date, end_date))
            except ValueError:
                return render(request, 'main/income.html', {
                    'incomes': [],
                    'error': 'Invalid date format.'
                })

        incomes = sorted(incomes, key=attrgetter('date'), reverse=True)

        context = {
            'incomes': incomes,
            'total_income': total_income,
            'this_month': this_month,
        }
        return render(request, 'main/income.html', context)


class ExpensesView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:expenses'

    def get(self, request):
        now = timezone.localtime(timezone.now())
        filt = request.GET.get('filter')
        start = request.GET.get('start')
        end = request.GET.get('end')

        expenses = Expense.objects.filter(user=request.user)
        this_month = sum(expense.amount for expense in expenses.filter(date__year=now.year, date__month=now.month))
        total_expense = sum(expense.amount for expense in expenses)

        if filt == 'day':
            expenses = expenses.filter(date=now.date())
            print(now.date())

        elif filt == 'week':
            start_of_week = now.date() - timedelta(days=now.weekday())
            end_of_week = start_of_week + timedelta(days=7)
            expenses = expenses.filter(date__range=(start_of_week, end_of_week))

        elif filt == 'month':
            expenses = expenses.filter(date__year=now.year, date__month=now.month)

        elif start or end:
            if not start:
                start = '0001-01-01'
            if not end:
                end = now.strftime('%Y-%m-%d')

            try:
                start_date = datetime.strptime(start, '%Y-%m-%d').date()
                end_date = datetime.strptime(end, '%Y-%m-%d').date()
                expenses = expenses.filter(date__range=(start_date, end_date))
            except ValueError:
                return render(request, 'main/expenses.html', {
                    'expenses': [],
                    'error': 'Invalid date format.'
                })
            
        expenses = sorted( expenses, key=attrgetter('date'), reverse=True)

        context = {
            'expenses': expenses,
            'total_expense': total_expense,
            'this_month': this_month,
        }
        return render(request, 'main/expenses.html', context)
    

class NewAccountView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:new_account'

    def get(self, request):
        form = AccountForm()
        return render(request, 'main/new_account.html', {'form': form})
    
    def post(self, request):
        form = AccountForm(request.POST, request.FILES)
        if form.is_valid():
            account = form.save(commit=False)
            account.user = request.user
            account.save()
            return redirect('main:transactions')
        return render(request, 'main/new_account.html', {'form': form})


class NewIncomeView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:new_income'

    def get(self, request):
        form = IncomeForm()
        return render(request, 'main/new_income.html', {'form': form})
    
    def post(self, request):
        form = IncomeForm(request.POST)
        if form.is_valid():
            income = form.save(commit=False)
            income.user = request.user
            income.save()
            return redirect('main:income')
        return render(request, 'main/new_income.html', {'form': form})
        
    
class NewExpenseView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:new_expense'

    def get(self, request):
        form = ExpenseForm()
        return render(request, 'main/new_expense.html', {'form': form})
    
    def post(self, request):
        form = ExpenseForm(request.POST)
        if form.is_valid():
            expense = form.save(commit=False)
            expense.user = request.user
            expense.save()
            return redirect('main:expenses')
        return render(request, 'main/new_expense.html', {'form': form})
    

class UpdateAccountView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:update_account'

    def get(self, request, account_id):
        account = get_object_or_404(Account, id=account_id)
        form = AccountForm(instance=account)
        return render(request, 'main/update_account.html', {'form': form})
    
    def post(self, request, account_id):
        account = get_object_or_404(Account, id=account_id)
        form = AccountForm(request.POST, request.FILES, instance=account)
        if form.is_valid():
            account = form.save()
            return redirect('main:transactions')
        return render(request, 'main:update_account.html', {'form': form})
    

class UpdateIncomeView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:update_income'

    def get(self, request, income_id):
        income = get_object_or_404(Income, id=income_id)
        form = IncomeForm(instance=income)
        return render(request, 'main/update_income.html', {'form': form})
    
    def post(self, request, income_id):
        income = get_object_or_404(Income, id=income_id)
        form = IncomeForm(request.POST, request.FILES, instance=income)
        if form.is_valid():
            form.save()
            return redirect('main:income')
        return render(request, 'main:update_income.html', {'form': form})
    

class UpdateExpenseView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:update_expense'

    def get(self, request, expense_id):
        expense = get_object_or_404(Expense, id=expense_id)
        form = ExpenseForm(instance=expense)
        return render(request, 'main/update_expense.html', {'form': form})
    
    def post(self, request, expense_id):
        expense = get_object_or_404(Expense, id=expense_id)
        form = ExpenseForm(request.POST, request.FILES, instance=expense)
        if form.is_valid():
            expense = form.save()
            return redirect('main:expenses')
        return render(request, 'main:update_expense.html', {'form': form})


class DeleteAccountView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:delete_account'

    def get(self, request, account_id):
        account = get_object_or_404(Account, id=account_id)
        return render(request, 'main/delete_account.html', {'account': account})

    def post(self, request, account_id):
        account = get_object_or_404(Account, id=account_id)
        account.delete()
        return redirect('main:transactions')


class DeleteIncomeView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:delete_income'

    def get(self, request, income_id):
        income = get_object_or_404(Income, id=income_id)
        return render(request, 'main/delete_income.html', {'income': income})

    def post(self, request, income_id):
        income = get_object_or_404(Income, id=income_id)
        income.delete()
        return redirect('main:income')


class DeleteExpenseView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:delete_expense'

    def get(self, request, expense_id):
        expense = get_object_or_404(Expense, id=expense_id)
        return render(request, 'main/delete_expense.html', {'expense': expense})

    def post(self, request, expense_id):
        expense = get_object_or_404(Expense, id=expense_id)
        expense.delete()
        return redirect('main:expenses')


class CategoriesView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:categories'

    def get(self, request):
        income_categories = IncomeCategory.objects.filter(user=request.user)
        expense_categories = ExpenseCategory.objects.filter(user=request.user)
        return render(request, 'main/categories.html', {
            'income_categories': income_categories,
            'expense_categories': expense_categories
        })


class NewIncomeCategoryView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:new_income_category'

    def get(self, request):
        form = IncomeCategoryForm()
        return render(request, 'main/new_income_category.html', {'form': form})
    
    def post(self, request):
        form = IncomeCategoryForm(request.POST)
        if form.is_valid():
            category = form.save(commit=False)
            category.user = request.user
            category.save()
            return redirect('main:categories')
        return render(request, 'main/new_income_category.html', {'form': form})
    

class NewExpenseCategoryView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:new_expense_category'

    def get(self, request):
        form = ExpenseCategoryForm()
        return render(request, 'main/new_expense_category.html', {'form': form})
    
    def post(self, request):
        form = ExpenseCategoryForm(request.POST)
        if form.is_valid():
            category = form.save(commit=False)
            category.user = request.user
            category.save()
            return redirect('main:categories')
        return render(request, 'main/new_expense_category.html', {'form': form})
    

class UpdateIncomeCategoryView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:update_income_category'

    def get(self, request, income_ctg_id):
        income_category = get_object_or_404(IncomeCategory, id=income_ctg_id)
        form = IncomeCategoryForm(instance=income_category)
        return render(request, 'main/update_income_category.html', {'form': form})
    
    def post(self, request, income_ctg_id):
        income_category = get_object_or_404(IncomeCategory, id=income_ctg_id)
        form = IncomeCategoryForm(request.POST, instance=income_category)
        if form.is_valid():
            form.save()
            return redirect('main:categories')
        return render(request, 'main/update_income_category.html', {'form': form})


class UpdateExpenseCategoryView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:update_expense_category'

    def get(self, request, expense_ctg_id):
        expense_category = get_object_or_404(ExpenseCategory, id=expense_ctg_id)
        form = ExpenseCategoryForm(instance=expense_category)
        return render(request, 'main/update_expense_category.html', {'form': form})
    
    def post(self, request, expense_ctg_id):
        expense_category = get_object_or_404(ExpenseCategory, id=expense_ctg_id)
        form = ExpenseCategoryForm(request.POST, instance=expense_category)
        if form.is_valid():
            form.save()
            return redirect('main:categories')
        return render(request, 'main/update_expense_category.html', {'form': form})
    

class DeleteIncomeCategoryView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:delete_income_category'

    def get(self, request, income_ctg_id):
        income_category = get_object_or_404(IncomeCategory, id=income_ctg_id)
        return render(request, 'main/delete_income_category.html', {'income_category': income_category})
    
    def post(self, request, income_ctg_id):
        income_category = get_object_or_404(IncomeCategory, id=income_ctg_id)
        income_category.delete()
        return redirect('main:categories')
    

class DeleteExpenseCategoryView(LoginRequiredMixin, View): # Hammasi OK
    login_url = 'users:login'
    next = 'main:delete_expense_category'

    def get(self, request, expense_ctg_id):
        expense_category = get_object_or_404(ExpenseCategory, id=expense_ctg_id)
        return render(request, 'main/delete_expense_category.html', {'income_category': expense_category})
    
    def post(self, request, expense_ctg_id):
        expense_category = get_object_or_404(ExpenseCategory, id=expense_ctg_id)
        expense_category.delete()
        return redirect('main:categories')

