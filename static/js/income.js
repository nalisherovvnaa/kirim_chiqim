// Demo kirim ma'lumotlari
let incomes = [
    { id: 1, date: '2023-06-15', source: 'salary', description: 'Monthly salary', amount: 2500.00 },
    { id: 2, date: '2023-06-10', source: 'freelance', description: 'Web design project', amount: 500.00 },
    { id: 3, date: '2023-06-05', source: 'investment', description: 'Dividends', amount: 120.50 }
];

// DOM elementlari
const incomeTable = document.getElementById('incomeTable').querySelector('tbody');
const addIncomeBtn = document.getElementById('addIncomeBtn');
const incomeForm = document.getElementById('incomeForm');
const totalIncomeElement = document.getElementById('totalIncome');
const monthlyIncomeElement = document.getElementById('monthlyIncome');
const primarySourceElement = document.getElementById('primarySource');
let incomeChart;

// Kirimlar ro'yxatini yangilash
function updateIncomeList() {
    incomeTable.innerHTML = '';
    
    incomes.forEach(income => {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>${formatDate(income.date)}</td>
            <td>${getSourceName(income.source)}</td>
            <td>${income.description}</td>
            <td class="text-success">+$${income.amount.toFixed(2)}</td>
            <td>
                <div class="actions">
                    <button class="btn btn-outline btn-sm edit-income-btn" data-id="${income.id}">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-outline btn-sm delete-income-btn" data-id="${income.id}">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        
        incomeTable.appendChild(row);
    });
    
    // Statistikani yangilash
    updateIncomeStats();
    updateIncomeChart();
    
    // Tugmalarga event listener qo'shish
    document.querySelectorAll('.edit-income-btn').forEach(btn => {
        btn.addEventListener('click', () => editIncome(btn.dataset.id));
    });
    
    document.querySelectorAll('.delete-income-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteIncome(btn.dataset.id));
    });
}

// Kirim statistikasini yangilash
function updateIncomeStats() {
    // Jami kirim
    const total = incomes.reduce((sum, income) => sum + income.amount, 0);
    totalIncomeElement.textContent = `$${total.toFixed(2)}`;
    
    // Oylik kirim
    const currentMonth = new Date().getMonth();
    const monthly = incomes
        .filter(income => new Date(income.date).getMonth() === currentMonth)
        .reduce((sum, income) => sum + income.amount, 0);
    monthlyIncomeElement.textContent = `$${monthly.toFixed(2)}`;
    
    // Asosiy manba
    const sources = {};
    incomes.forEach(income => {
        sources[income.source] = (sources[income.source] || 0) + income.amount;
    });
    
    if (Object.keys(sources).length > 0) {
        const primary = Object.entries(sources).reduce((a, b) => a[1] > b[1] ? a : b);
        primarySourceElement.textContent = `${getSourceName(primary[0])} (${((primary[1] / total) * 100).toFixed(1)}%)`;
    }
}

// Kirim diagrammasini yangilash
function updateIncomeChart() {
    const ctx = document.getElementById('incomeSourceChart').getContext('2d');
    
    // Manbalar bo'yicha guruhlash
    const sources = {};
    incomes.forEach(income => {
        sources[income.source] = (sources[income.source] || 0) + income.amount;
    });
    
    const labels = Object.keys(sources).map(source => getSourceName(source));
    const data = Object.values(sources);
    const colors = ['#4cc9f0', '#4895ef', '#4361ee', '#3f37c9'];
    
    if (incomeChart) {
        incomeChart.destroy();
    }
    
    incomeChart = new Chart(ctx, {
        type: 'pie',
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

// Manba nomini olish
function getSourceName(source) {
    const sources = {
        'salary': { en: 'Salary', uz: 'Maosh', ru: 'Зарплата' },
        'freelance': { en: 'Freelance', uz: 'Freelance', ru: 'Фриланс' },
        'investment': { en: 'Investment', uz: 'Investitsiya', ru: 'Инвестиция' }
    };
    
    const lang = document.documentElement.lang;
    return sources[source][lang] || source;
}

// Sana formatlash
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString(undefined, options);
}

// Yangi kirim qo'shish
function addIncome(newIncome) {
    // ID generatsiya qilish
    newIncome.id = incomes.length > 0 ? 
        Math.max(...incomes.map(i => i.id)) + 1 : 1;
    
    incomes.push(newIncome);
    updateIncomeList();
}

// Kirimni tahrirlash
function editIncome(id) {
    const income = incomes.find(i => i.id === parseInt(id));
    if (income) {
        // Modalni to'ldirish
        document.getElementById('incomeSource').value = income.source;
        document.getElementById('incomeAmount').value = income.amount;
        document.getElementById('incomeDate').value = income.date;
        document.getElementById('incomeDescription').value = income.description;
        
        // Modalni ochish
        document.getElementById('addIncomeModal').classList.add('active');
        
        // TODO: Tahrirlash rejimini sozlash
    }
}

// Kirimni o'chirish
function deleteIncome(id) {
    if (confirm('Are you sure you want to delete this income?')) {
        incomes = incomes.filter(i => i.id !== parseInt(id));
        updateIncomeList();
    }
}

// Formni yuborish
incomeForm.addEventListener('submit', function(e) {
    e.preventDefault();
    
    const newIncome = {
        source: document.getElementById('incomeSource').value,
        amount: parseFloat(document.getElementById('incomeAmount').value),
        date: document.getElementById('incomeDate').value,
        description: document.getElementById('incomeDescription').value
    };
    
    addIncome(newIncome);
    document.getElementById('addIncomeModal').classList.remove('active');
    incomeForm.reset();
});

// Modalni ochish
addIncomeBtn.addEventListener('click', () => {
    document.getElementById('addIncomeModal').classList.add('active');
});

// Dastlabki yuklash
updateIncomeList();