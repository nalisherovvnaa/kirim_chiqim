// Demo tranzaksiyalar
let transactions = [
    {
        id: 1,
        date: '2023-06-15',
        description: 'Salary Deposit',
        category: 'salary',
        type: 'income',
        amount: 3200.00
    },
    {
        id: 2,
        date: '2023-06-14',
        description: 'Grocery Shopping',
        category: 'food',
        type: 'expense',
        amount: 125.75
    },
    // Qo'shimcha tranzaksiyalar...
];

// DOM elementlari
const transactionsTable = document.getElementById('transactionsTable').querySelector('tbody');
const filterButtons = document.querySelectorAll('.filter-btn');
const customDateRange = document.getElementById('customDateRange');
const addTransactionBtn = document.getElementById('addTransactionBtn');

// Tranzaksiyalar ro'yxatini yangilash
function updateTransactionsList(filter = 'all', startDate = null, endDate = null) {
    transactionsTable.innerHTML = '';
    
    let filteredTransactions = [...transactions];
    
    // Filtrlash
    if (filter !== 'all') {
        const now = new Date();
        filteredTransactions = filteredTransactions.filter(t => {
            const transDate = new Date(t.date);
            
            switch(filter) {
                case 'day':
                    return transDate.toDateString() === now.toDateString();
                case 'week':
                    const weekStart = new Date(now.setDate(now.getDate() - now.getDay()));
                    return transDate >= weekStart;
                case 'month':
                    return transDate.getMonth() === now.getMonth() && 
                            transDate.getFullYear() === now.getFullYear();
                case 'year':
                    return transDate.getFullYear() === now.getFullYear();
                case 'custom':
                    return startDate && endDate && 
                            transDate >= new Date(startDate) && 
                            transDate <= new Date(endDate);
                default:
                    return true;
            }
        });
    }
    
    // Jadvalni to'ldirish
    filteredTransactions.forEach(transaction => {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>${formatDate(transaction.date)}</td>
            <td>${transaction.description}</td>
            <td>
                <span class="badge ${transaction.type === 'income' ? 'badge-success' : 'badge-danger'}">
                    ${getCategoryName(transaction.category)}
                </span>
            </td>
            <td class="${transaction.type === 'income' ? 'text-success' : 'text-danger'}">
                ${transaction.type === 'income' ? '+' : '-'}$${transaction.amount.toFixed(2)}
            </td>
            <td>
                <div class="actions">
                    <button class="btn btn-outline btn-sm edit-btn" data-id="${transaction.id}">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-outline btn-sm delete-btn" data-id="${transaction.id}">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        
        transactionsTable.appendChild(row);
    });
    
    // Edit/Delete tugmalariga event listener qo'shish
    document.querySelectorAll('.edit-btn').forEach(btn => {
        btn.addEventListener('click', () => editTransaction(btn.dataset.id));
    });
    
    document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteTransaction(btn.dataset.id));
    });
}

// Sana formatlash
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString(undefined, options);
}

// Kategoriya nomini olish
function getCategoryName(category) {
    const categories = {
        'salary': { en: 'Salary', uz: 'Maosh', ru: 'Зарплата' },
        'food': { en: 'Food', uz: 'Oziq-ovqat', ru: 'Еда' },
        // Qo'shimcha kategoriyalar...
    };
    
    const lang = document.documentElement.lang;
    return categories[category][lang] || category;
}

// Filtrlash tugmalari
filterButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        filterButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        if (btn.dataset.filter === 'custom') {
            customDateRange.style.display = 'flex';
        } else {
            customDateRange.style.display = 'none';
            updateTransactionsList(btn.dataset.filter);
        }
    });
});

// Maxsus sana oralig'ini qo'llash
document.getElementById('applyDateRange').addEventListener('click', () => {
    const startDate = document.getElementById('startDate').value;
    const endDate = document.getElementById('endDate').value;
    
    if (startDate && endDate) {
        updateTransactionsList('custom', startDate, endDate);
    }
});

// Yangi tranzaksiya qo'shish
addTransactionBtn.addEventListener('click', () => {
    // Modal oynani ochish
    document.getElementById('addTransactionModal').classList.add('active');
});

// Dastlabki tranzaksiyalarni yuklash
updateTransactionsList();