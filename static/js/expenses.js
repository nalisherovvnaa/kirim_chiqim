// Demo chiqim 
let expenses = [
    { id: 1, date: '2023-06-15', category: 'food', description: 'Grocery shopping', amount: 85.75 },
    { id: 2, date: '2023-06-12', category: 'utilities', description: 'Electric bill', amount: 65.20 },
    { id: 3, date: '2023-06-10', category: 'transport', description: 'Fuel', amount: 40.00 }
];

// Byudjet 
const monthlyBudget = 2000;
let budgetSpent = expenses.reduce((sum, exp) => sum + exp.amount, 0);

// DOM elementlari
const expenseTable = document.getElementById('expenseTable').querySelector('tbody');
const addExpenseBtn = document.getElementById('addExpenseBtn');
const expenseForm = document.getElementById('expenseForm');
const totalExpensesElement = document.getElementById('totalExpenses');
const monthlyExpensesElement = document.getElementById('monthlyExpenses');
const mainCategoryElement = document.getElementById('mainCategory');
const budgetStatusElement = document.getElementById('budgetStatus');
const budgetProgressElement = document.getElementById('budgetProgress');
const budgetPercentageElement = document.getElementById('budgetPercentage');
let expenseChart;

// Chiqimlar royxatini yengilsh
function updateExpenseList() {
    expenseTable.innerHTML = '';
    
    expenses.forEach(expense => {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>${formatDate(expense.date)}</td>
            <td>${getCategoryName(expense.category)}</td>
            <td>${expense.description}</td>
            <td class="text-danger">-$${expense.amount.toFixed(2)}</td>
            <td>
                <div class="actions">
                    <button class="btn btn-outline btn-sm edit-expense-btn" data-id="${expense.id}">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-outline btn-sm delete-expense-btn" data-id="${expense.id}">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        
        expenseTable.appendChild(row);
    });
    
    // Statistikani yengilsh
    updateExpenseStats();
    updateBudgetInfo();
    updateExpenseChart();
    
    // Tugmalarga event listener qoshish
    document.querySelectorAll('.edit-expense-btn').forEach(btn => {
        btn.addEventListener('click', () => editExpense(btn.dataset.id));
    });
    
    document.querySelectorAll('.delete-expense-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteExpense(btn.dataset.id));
    });
}

// Chiqim statistikasini yengilsh
function updateExpenseStats() {
    // Jami chiqim
    const total = expenses.reduce((sum, expense) => sum + expense.amount, 0);
    totalExpensesElement.textContent = `$${total.toFixed(2)}`;
    
    // Oylik chiqim
    const currentMonth = new Date().getMonth();
    const monthly = expenses
        .filter(expense => new Date(expense.date).getMonth() === currentMonth)
        .reduce((sum, expense) => sum + expense.amount, 0);
    monthlyExpensesElement.textContent = `$${monthly.toFixed(2)}`;
    
    // Asosiy toifa
    const categories = {};
    expenses.forEach(expense => {
        categories[expense.category] = (categories[expense.category] || 0) + expense.amount;
    });
    
    if (Object.keys(categories).length > 0) {
        const main = Object.entries(categories).reduce((a, b) => a[1] > b[1] ? a : b);
        mainCategoryElement.textContent = `${getCategoryName(main[0])} (${((main[1] / total) * 100).toFixed(1)}%)`;
    }
}

// Byudjet malumotlarini yengilsh
function updateBudgetInfo() {
    const currentMonth = new Date().getMonth();
    budgetSpent = expenses
        .filter(expense => new Date(expense.date).getMonth() === currentMonth)
        .reduce((sum, expense) => sum + expense.amount, 0);
    
    const percentage = (budgetSpent / monthlyBudget) * 100;
    const remaining = monthlyBudget - budgetSpent;
    
    budgetStatusElement.textContent = `$${budgetSpent.toFixed(2)} / $${monthlyBudget.toFixed(2)}`;
    budgetProgressElement.style.width = `${Math.min(percentage, 100)}%`;
    
    if (percentage > 90) {
        budgetProgressElement.style.backgroundColor = '#f72585';
    } else if (percentage > 70) {
        budgetProgressElement.style.backgroundColor = '#f8961e';
    } else {
        budgetProgressElement.style.backgroundColor = '#43aa8b';
    }
    
    // Tilga mos ravishda matn
    const lang = document.documentElement.lang;
    if (lang === 'uz') {
        budgetPercentageElement.textContent = `${percentage.toFixed(0)}% sarflandi`;
        if (remaining > 0) {
            budgetPercentageElement.textContent += `, $${remaining.toFixed(2)} qoldi`;
        } else {
            budgetPercentageElement.textContent += `, byudjetdan ${Math.abs(remaining).toFixed(2)} oshib ketdi`;
        }
    } else if (lang === 'ru') {
        budgetPercentageElement.textContent = `${percentage.toFixed(0)}% потрачено`;
        if (remaining > 0) {
            budgetPercentageElement.textContent += `, $${remaining.toFixed(2)} осталось`;
        } else {
            budgetPercentageElement.textContent += `, превышение на $${Math.abs(remaining).toFixed(2)}`;
        }
    } else {
        budgetPercentageElement.textContent = `${percentage.toFixed(0)}% spent`;
        if (remaining > 0) {
            budgetPercentageElement.textContent += `, $${remaining.toFixed(2)} remaining`;
        } else {
            budgetPercentageElement.textContent += `, $${Math.abs(remaining).toFixed(2)} over budget`;
        }
    }
}

// Chiqim diagrammasini yangilash
function updateExpenseChart() {
    const ctx = document.getElementById('expenseCategoryChart').getContext('2d');
    
    // Toifalar boyicha guruhlash
    const categories = {};
    expenses.forEach(expense => {
        categories[expense.category] = (categories[expense.category] || 0) + expense.amount;
    });
    
    const labels = Object.keys(categories).map(cat => getCategoryName(cat));
    const data = Object.values(categories);
    const colors = ['#f72585', '#b5179e', '#7209b7', '#560bad'];
    
    if (expenseChart) {
        expenseChart.destroy();
    }
    
    expenseChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const value = context.raw;
                            const percentage = Math.round((value / total) * 100);
                            return `${context.label}: $${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Toifa nomini olish
function getCategoryName(category) {
    const categories = {
        'food': { en: 'Food & Dining', uz: 'Oziq-ovqat', ru: 'Еда' },
        'transport': { en: 'Transport', uz: 'Transport', ru: 'Транспорт' },
        'utilities': { en: 'Utilities', uz: 'Kommunal', ru: 'Коммунальные' }
    };
    
    const lang = document.documentElement.lang;
    return categories[category][lang] || category;
}

// Sana formatlash
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString(undefined, options);
}

// Yangi chiqim qo'shish
function addExpense(newExpense) {
    // ID generatsiya qilish
    newExpense.id = expenses.length > 0 ? 
        Math.max(...expenses.map(e => e.id)) + 1 : 1;
    
    expenses.push(newExpense);
    updateExpenseList();
}

// Chiqimni tahrirlash
function editExpense(id) {
    const expense = expenses.find(e => e.id === parseInt(id));
    if (expense) {
        // Modalni to'ldirish
        document.getElementById('expenseCategory').value = expense.category;
        document.getElementById('expenseAmount').value = expense.amount;
        document.getElementById('expenseDate').value = expense.date;
        document.getElementById('expenseDescription').value = expense.description;
        
        // Modalni ochish
        document.getElementById('addExpenseModal').classList.add('active');
        
        // TODO: Tahrirlash rejimini sozlash
    }
}

// Chiqimni o'chirish
function deleteExpense(id) {
    if (confirm('Are you sure you want to delete this expense?')) {
        expenses = expenses.filter(e => e.id !== parseInt(id));
        updateExpenseList();
    }
}

// Formni yuborish
expenseForm.addEventListener('submit', function(e) {
    e.preventDefault();
    
    const newExpense = {
        category: document.getElementById('expenseCategory').value,
        amount: parseFloat(document.getElementById('expenseAmount').value),
        date: document.getElementById('expenseDate').value,
        description: document.getElementById('expenseDescription').value
    };
    
    addExpense(newExpense);
    document.getElementById('addExpenseModal').classList.remove('active');
    expenseForm.reset();
});

// Modalni ochish
addExpenseBtn.addEventListener('click', () => {
    document.getElementById('addExpenseModal').classList.add('active');
});

// Dastlabki yuklash
updateExpenseList();
    