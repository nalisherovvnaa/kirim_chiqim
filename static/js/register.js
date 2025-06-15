// Language Toggle
const languageToggle = document.querySelector('.language-toggle');
const languageMenu = document.querySelector('.language-menu');

if (languageToggle && languageMenu) {
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
}

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
}

// Saqlangan til preferencesini tekshirish
const savedLang = localStorage.getItem('language') || 'en';
setLanguage(savedLang);