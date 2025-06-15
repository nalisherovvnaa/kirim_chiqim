from datetime import datetime
from itertools import chain
from operator import attrgetter
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.shortcuts import get_object_or_404
from users.models import CustomUser
from main.models import Account, IncomeCategory, ExpenseCategory, Income, Expense
from .serializers import TransactionSerializer, AccountSerializer, IncomeCategorySerializer, ExpenseCategorySerializer, IncomeSerializer, ExpenseSerializer
from django.utils import timezone



# Create your views here.

class MainView(APIView):  # Hammasi OK
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def get(self, request):
        user = request.user
        now = timezone.now()
        incomes = Income.objects.filter(user=user, date__year=now.year, date__month=now.month)
        expenses = Expense.objects.filter(user=user, date__year=now.year, date__month=now.month)
        accounts = Account.objects.filter(user=user)
        total_income, total_expense, total_balance = 0, 0, 0
        for income in incomes:
            total_income += income.amount
        for expense in expenses:
            total_expense += expense.amount
        for account in accounts:
            total_balance += account.amount
        
        return Response({
            'total_income': total_income,
            'total_expense': total_expense,
            'total_balance': total_balance,
            }, status.HTTP_200_OK)


class TransactionsView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def post(self, request):
        now = timezone.localtime(timezone.now())
        data = request.data
        filt = data.get('filter')
        start = data.get('start')
        end = data.get('end')

        accounts = Account.objects.filter(user=request.user)
        incomes = Income.objects.filter(user=request.user)
        expenses = Expense.objects.filter(user=request.user)

        if filt == 'day':
            incomes = incomes.filter(date=now.date())
            expenses = expenses.filter(date=now.date())

        elif filt == 'week':
            start_of_week = now.date() - timezone.timedelta(days=now.weekday())
            end_of_week = start_of_week + timezone.timedelta(days=7)
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
                accounts = AccountSerializer(accounts, many=True)
                return Response({
                    'transactions': [],
                    'accounts': accounts.data,
                    'error': 'Invalid date format.'
                }, status.HTTP_400_BAD_REQUEST)

        transactions = sorted(
            chain(incomes, expenses),
            key=attrgetter('date'),
            reverse=True
        )

        transactions = TransactionSerializer(transactions, many=True)
        accounts = AccountSerializer(accounts, many=True)
        return Response({
                    'transactions': transactions.data,
                    'accounts': accounts.data,
                    'message': 'Transactions and accounts.'
                }, status.HTTP_400_BAD_REQUEST)


class IncomeView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def post(self, request):
        now = timezone.localtime(timezone.now())
        data = request.data
        filt = data.get('filter')
        start = data.get('start')
        end = data.get('end')

        incomes = Income.objects.filter(user=request.user)
        total_income = sum(income.amount for income in incomes)
        this_month = sum(income.amount for income in incomes.filter(date__year=now.year, date__month=now.month))

        if filt == 'day':
            incomes = incomes.filter(date=now.date())

        elif filt == 'week':
            start_of_week = now.date() - timezone.timedelta(days=now.weekday())
            end_of_week = start_of_week + timezone.timedelta(days=7)
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
                return Response({
                    'incomes': [],
                    'total_income': total_income,
                    'this_month': this_month,
                    'error': 'Invalid date format.'
                    },status.HTTP_400_BAD_REQUEST)

        incomes = sorted(incomes, key=attrgetter('date'), reverse=True)
        serializer = IncomeSerializer(incomes, many=True)

        return Response({
            'incomes': serializer.data,
            'total_income': total_income,
            'this_month': this_month,
            }, status.HTTP_200_OK)


class ExpensesView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def post(self, request):
        now = timezone.localtime(timezone.now())
        data = request.data
        filt = data.get('filter')
        start = data.get('start')
        end = data.get('end')

        expenses = Expense.objects.filter(user=request.user)
        this_month = sum(expense.amount for expense in expenses.filter(date__year=now.year, date__month=now.month))
        total_expense = sum(expense.amount for expense in expenses)

        if filt == 'day':
            expenses = expenses.filter(date=now.date())
            print(now.date())

        elif filt == 'week':
            start_of_week = now.date() - timezone.timedelta(days=now.weekday())
            end_of_week = start_of_week + timezone.timedelta(days=7)
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
                return Response({
                    'expenses': [],
                    'total_expense': total_expense,
                    'this_month': this_month,
                    'error': 'Invalid date format.'
                    },status.HTTP_400_BAD_REQUEST)
            
        expenses = sorted( expenses, key=attrgetter('date'), reverse=True)
        serializer = ExpenseSerializer(expenses, many=True)


        return Response({
            'expenses': serializer.data,
            'total_expense': total_expense,
            'this_month': this_month,
            }, status.HTTP_200_OK)
    

class NewAccountView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,
    
    def post(self, request):
        serializer = AccountSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response({'data': serializer.data, 'message': 'Account created!'}, status.HTTP_201_CREATED)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)


class NewIncomeView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,
    
    def post(self, request):
        serializer = IncomeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response({'data': serializer.data, 'message': 'Income created!'}, status.HTTP_201_CREATED)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)
        
    
class NewExpenseView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def post(self, request):
        serializer = ExpenseSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response({'data': serializer.data, 'message': 'Expense created!'}, status.HTTP_201_CREATED)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)
    

class UpdateAccountView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def put(self, request, account_id):
        account = Account.objects.filter(user=request.user, id=account_id).first()
        serializer = AccountSerializer(account, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'message': 'Account updated!'}, status.HTTP_200_OK)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)

    def patch(self, request, account_id):
        account = Account.objects.filter(user=request.user, id=account_id).first()
        serializer = AccountSerializer(account, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'message': 'Account updated!'}, status.HTTP_200_OK)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)
    

class UpdateIncomeView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def put(self, request, income_id):
        income = Income.objects.filter(user=request.user, id=income_id).first()
        serializer = IncomeSerializer(income, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'message': 'Income updated!'}, status.HTTP_200_OK)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)

    def patch(self, request, income_id):
        income = Income.objects.filter(user=request.user, id=income_id).first()
        serializer = IncomeSerializer(income, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'message': 'Income updated!'}, status.HTTP_200_OK)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)


class UpdateExpenseView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def put(self, request, expense_id):
        expense = Expense.objects.filter(user=request.user, id=expense_id).first()
        serializer = ExpenseSerializer(expense, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'message': 'Expense updated!'}, status.HTTP_200_OK)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)

    def patch(self, request, expense_id):
        expense = Expense.objects.filter(user=request.user, id=expense_id).first()
        serializer = ExpenseSerializer(expense, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'message': 'Expense updated!'}, status.HTTP_200_OK)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)


class DeleteAccountView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def delete(self, request, account_id):
        account = get_object_or_404(Account, user=request.user, id=account_id)
        account.delete()
        return Response({'data': None, 'message': 'Account deleted!'}, status.HTTP_200_OK)


class DeleteIncomeView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def delete(self, request, income_id):
        income = get_object_or_404(Income, user=request.user, id=income_id)
        income.delete()
        return Response({'data': None, 'message': 'Income deleted!'}, status.HTTP_200_OK)


class DeleteExpenseView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def delete(self, request, expense_id):
        expense = get_object_or_404(Expense, user=request.user, id=expense_id)
        expense.delete()
        return Response({'data': None, 'message': 'Expense deleted!'}, status.HTTP_200_OK)


class CategoriesView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def get(self, request):
        income_categories = IncomeCategory.objects.filter(user=request.user)
        expense_categories = ExpenseCategory.objects.filter(user=request.user)
        income_ctg_serializer = IncomeCategorySerializer(income_categories, many=True)
        expense_ctg_serializer = ExpenseCategorySerializer(expense_categories, many=True)
        return Response({
            'income_categories': income_ctg_serializer.data,
            'expense_categories': expense_ctg_serializer.data
            }, status.HTTP_200_OK)


class NewIncomeCategoryView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def post(self, request):
        serializer = IncomeCategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response({'data': serializer.data, 'message': 'Income category created!'}, status.HTTP_201_CREATED)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)


class NewExpenseCategoryView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def post(self, request):
        serializer = ExpenseCategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response({'data': serializer.data, 'message': 'Expense category created!'}, status.HTTP_201_CREATED)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)
    

class UpdateIncomeCategoryView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def put(self, request, income_ctg_id):
        income_ctg = IncomeCategory.objects.filter(user=request.user, id=income_ctg_id).first()
        serializer = IncomeCategorySerializer(income_ctg, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'message': 'Income category updated!'}, status.HTTP_200_OK)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)

    def patch(self, request, income_ctg_id):
        income_ctg = IncomeCategory.objects.filter(user=request.user, id=income_ctg_id).first()
        serializer = IncomeCategorySerializer(income_ctg, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'message': 'Income category updated!'}, status.HTTP_200_OK)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)


class UpdateExpenseCategoryView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def put(self, request, expense_ctg_id):
        expense_ctg = ExpenseCategory.objects.filter(user=request.user, id=expense_ctg_id).first()
        serializer = ExpenseCategorySerializer(expense_ctg, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'message': 'Expense category updated!'}, status.HTTP_200_OK)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)

    def patch(self, request, expense_ctg_id):
        expense_ctg = ExpenseCategory.objects.filter(user=request.user, id=expense_ctg_id).first()
        serializer = ExpenseCategorySerializer(expense_ctg, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'message': 'Expense category updated!'}, status.HTTP_200_OK)
        
        return Response({'error': serializer.errors}, status.HTTP_400_BAD_REQUEST)
    

class DeleteIncomeCategoryView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,
    
    def delete(self, request, income_ctg_id):
        income_category = get_object_or_404(IncomeCategory, id=income_ctg_id)
        income_category.delete()
        return Response({'data': None, 'message': 'Income deleted!'}, status.HTTP_200_OK)
    

class DeleteExpenseCategoryView(APIView): # Hammasi OK 
    permission_classes = IsAuthenticated,
    authentication_classes = TokenAuthentication,

    def delete(self, request, expense_ctg_id):
        expense_category = get_object_or_404(ExpenseCategory, id=expense_ctg_id)
        expense_category.delete()
        return Response({'data': None, 'message': 'Expense deleted!'}, status.HTTP_200_OK)

