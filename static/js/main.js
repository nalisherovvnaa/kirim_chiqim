// Theme Toggle
const themeToggle = document.querySelector('.theme-toggle');
const html = document.documentElement;

// Check for saved theme preference or use preferred color scheme
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
const savedTheme = localStorage.getItem('theme') || (prefersDark ? 'dark' : 'light');
html.setAttribute('data-theme', savedTheme);

// Update icon based on current theme
updateThemeIcon();

themeToggle.addEventListener('click', () => {
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon();
    updateThemeText();
});

function updateThemeIcon() {
    const currentTheme = html.getAttribute('data-theme');
    themeToggle.innerHTML = currentTheme === 'dark' ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
}

function updateThemeText() {
    const currentTheme = html.getAttribute('data-theme');
    document.getElementById('viewTheme').textContent = currentTheme === 'dark' ? 'Dark' : 'Light';
}

// Language Toggle
const languageToggle = document.querySelector('.language-toggle');
const languageMenu = document.querySelector('.language-menu');

languageToggle.addEventListener('click', (e) => {
    e.stopPropagation();
    languageMenu.classList.toggle('active');
});

// Tashqariga bosilganda menyu yopilishi
document.addEventListener('click', () => {
    languageMenu.classList.remove('active');
});

// Tilni o'zgartirish
document.querySelectorAll('.language-menu a').forEach(item => {
    item.addEventListener('click', function(e) {
        e.preventDefault();
        const lang = this.getAttribute('data-lang');
        setLanguage(lang);
        languageMenu.classList.remove('active');
    });
});

function setLanguage(lang) {
    // Barcha tillarni yashirish
    document.querySelectorAll('.en, .uz, .ru').forEach(el => {
        el.style.display = 'none';
    });
    
    // Tanlangan tilni ko'rsatish
    document.querySelectorAll(`.${lang}`).forEach(el => {
        el.style.display = 'inline';
    });
    
    // HTML til atributini yangilash
    document.documentElement.lang = lang;
    
    // Til preferencesini saqlash
    localStorage.setItem('language', lang);
    
    // Til matnini yangilash
    updateLanguageText(lang);
}

function updateLanguageText(lang) {
    const languages = {
        'en': 'English',
        'uz': 'O\'zbekcha',
        'ru': 'Русский'
    };
    document.getElementById('viewLanguage').textContent = languages[lang];
}

// Saqlangan til preferencesini tekshirish
const savedLang = localStorage.getItem('language') || 'en';
setLanguage(savedLang);

// Profile Edit Toggle
const editPersonalInfoBtn = document.getElementById('editPersonalInfoBtn');
const personalInfoView = document.getElementById('personalInfoView');
const personalInfoForm = document.getElementById('personalInfoForm');
const cancelPersonalInfoEdit = document.getElementById('cancelPersonalInfoEdit');

editPersonalInfoBtn.addEventListener('click', () => {
    personalInfoView.style.display = 'none';
    personalInfoForm.style.display = 'block';
});

cancelPersonalInfoEdit.addEventListener('click', () => {
    personalInfoView.style.display = 'grid';
    personalInfoForm.style.display = 'none';
});

// Formni yuborish
personalInfoForm.addEventListener('submit', function(e) {
    e.preventDefault();
    
    // Yangi qiymatlarni olish
    const fullName = document.getElementById('fullName').value;
    const email = document.getElementById('email').value;
    const phone = document.getElementById('phone').value;
    const birthDate = new Date(document.getElementById('birthDate').value);
    const address = document.getElementById('address').value;
    
    // Ko'rinishni yangilash
    document.getElementById('viewFullName').textContent = fullName;
    document.getElementById('viewEmail').textContent = email;
    document.getElementById('viewPhone').textContent = phone;
    document.getElementById('viewBirthDate').textContent = birthDate.toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric'
    });
    document.getElementById('viewAddress').textContent = address;
    
    // Profilni yangilash
    document.getElementById('profileName').textContent = fullName;
    document.getElementById('profileEmail').textContent = email;
    
    // Avatar textini yangilash
    const nameParts = fullName.split(' ');
    const avatarText = (nameParts[0][0] + (nameParts.length > 1 ? nameParts[1][0] : '')).toUpperCase();
    document.querySelector('.avatar-text').textContent = avatarText;
    document.querySelector('.preview-text').textContent = avatarText;
    
    // Ko'rinishga qaytish
    personalInfoView.style.display = 'grid';
    personalInfoForm.style.display = 'none';
    
    // TODO: API orqali serverga yuborish
});

// Change Password Modal
const changePasswordBtns = [document.getElementById('changePasswordBtn'), 
                            document.getElementById('changePasswordBtn2')];
const changePasswordModal = document.getElementById('changePasswordModal');
const passwordForm = document.getElementById('passwordForm');

changePasswordBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        changePasswordModal.classList.add('active');
    });
});

// Change Avatar Modal
const profileAvatar = document.getElementById('profileAvatar');
const changeAvatarModal = document.getElementById('changeAvatarModal');
const avatarInput = document.getElementById('avatarInput');
const avatarPreview = document.getElementById('avatarPreview');

profileAvatar.addEventListener('click', () => {
    changeAvatarModal.classList.add('active');
});

avatarInput.addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(event) {
            if (avatarPreview.querySelector('img')) {
                avatarPreview.querySelector('img').src = event.target.result;
            } else {
                const img = document.createElement('img');
                img.src = event.target.result;
                avatarPreview.innerHTML = '';
                avatarPreview.appendChild(img);
            }
            avatarPreview.querySelector('.preview-text').style.display = 'none';
        };
        reader.readAsDataURL(file);
    }
});

// Logout Modal
const logoutBtn = document.getElementById('logoutBtn');
const logoutModal = document.getElementById('logoutModal');

logoutBtn.addEventListener('click', () => {
    logoutModal.classList.add('active');
});

// Modal yopish funksiyasi
function closeModal(modal) {
    modal.classList.remove('active');
}

// Barcha modal yopish tugmalari
document.querySelectorAll('.modal-close').forEach(closeBtn => {
    closeBtn.addEventListener('click', function() {
        closeModal(this.closest('.modal'));
    });
});

// Tashqariga bosilganda modalni yopish
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', function(e) {
        if (e.target === this) {
            closeModal(this);
        }
    });
});

// Dastlabki yuklashda ma'lumotlarni yangilash
updateThemeText();