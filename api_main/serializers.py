from rest_framework import serializers
from main.models import CurrencyChoices, Account, IncomeIconChoices, ExpenseIconChoices, IncomeCategory, ExpenseCategory, Income, Expense


class TransactionSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    amount = serializers.DecimalField(max_digits=12, decimal_places=2)
    date = serializers.DateField()
    description = serializers.CharField(allow_blank=True, allow_null=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    account_name = serializers.CharField(source='account_type.type', read_only=True)
    type = serializers.SerializerMethodField()

    def get_type(self, obj):
        if isinstance(obj, Income):
            return "Income"
        elif isinstance(obj, Expense):
            return "Expense"
        return "Unknown"


class AccountSerializer(serializers.ModelSerializer):
    currency_type = serializers.ChoiceField(choices=CurrencyChoices.choices)

    class Meta:
        model = Account
        fields = ['currency_type', 'type', 'amount', 'description']
        read_only_fields = ['user']


class IncomeCategorySerializer(serializers.ModelSerializer):
    icon = serializers.ChoiceField(choices=IncomeIconChoices.choices)

    class Meta:
        model = IncomeCategory
        fields = ['name', 'icon']
        read_only_fields = ['user']


class ExpenseCategorySerializer(serializers.ModelSerializer):
    icon = serializers.ChoiceField(choices=ExpenseIconChoices.choices)

    class Meta:
        model = ExpenseCategory
        fields = ['name', 'icon']
        read_only_fields = ['user']


class IncomeSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)
    account_type_name = serializers.CharField(source='account_type.type', read_only=True)

    class Meta:
        model = Income
        fields = ['category', 'category_name', 'account_type', 'account_type_name', 'amount', 'date', 'description']
        read_only_fields = ['user']


class ExpenseSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)
    account_type_name = serializers.CharField(source='account_type.type', read_only=True)

    class Meta:
        model = Expense
        fields = ['category', 'category_name', 'account_type', 'account_type_name', 'amount', 'date', 'description']
        read_only_fields = ['user']