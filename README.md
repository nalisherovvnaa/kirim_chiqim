# MyBalanse

MyBalanse — bu foydalanuvchilarning moliyaviy kirim-chiqimlarini boshqarish uchun mo‘ljallangan veb-ilova. Loyiha Django frameworki asosida yaratilgan bo‘lib, MVT (Model-View-Template) arxitekturasi va RESTful API integratsiyasini o‘z ichiga oladi.

## 🧩 Asosiy xususiyatlar

- **Foydalanuvchi autentifikatsiyasi**: Ro‘yxatdan o‘tish, tizimga kirish va chiqish funksiyalari.
- **Kirim va chiqimlar boshqaruvi**: Foydalanuvchilar o‘zlarining moliyaviy operatsiyalarini qo‘shish, tahrirlash va o‘chirish imkoniyatiga ega.
- **API integratsiyasi**: RESTful API orqali ma'lumotlar bilan ishlash imkoniyati.
- **Admin panel**: Django admin paneli orqali ma'lumotlarni boshqarish.
- **Responsive dizayn**: Turli qurilmalarda to‘g‘ri ishlaydigan foydalanuvchi interfeysi.

## 🛠 Texnologiyalar

- **Backend**: Django (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Ma'lumotlar bazasi**: SQLite
- **API**: Django REST Framework

## 📁 Loyiha tuzilmasi

```
MyBalanse/
├── api_main/           # Asosiy API endpointlari
├── api_users/          # Foydalanuvchilar uchun API endpointlari
├── config/             # Django konfiguratsiya fayllari
├── locale/             # Til fayllari
├── main/               # Asosiy ilova logikasi
├── media/              # Yuklangan fayllar
├── static/             # Statik fayllar (CSS, JS, rasmlar)
├── templates/          # HTML shablonlar
├── users/              # Foydalanuvchi modeli va autentifikatsiya
├── services.py         # Qo‘shimcha xizmatlar
├── manage.py           # Django boshqaruv fayli
└── db.sqlite3          # Ma'lumotlar bazasi
```

## 🚀 O‘rnatish va ishga tushirish

1. **Repositoryni klonlash**:

   ```bash
   git clone https://github.com/swe-samandar/MyBalanse.git
   cd MyBalanse
   ```

2. **Virtual muhit yaratish va faollashtirish**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows uchun: venv\Scripts\activate
   ```

3. **Talab qilinadigan kutubxonalarni o‘rnatish**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Ma'lumotlar bazasini yaratish**:

   ```bash
   python manage.py migrate
   ```

5. **Superfoydalanuvchi yaratish**:

   ```bash
   python manage.py createsuperuser
   ```

6. **Serverni ishga tushirish**:

   ```bash
   python manage.py runserver
   ```

   Brauzeringizda `http://127.0.0.1:8000/` manziliga o‘ting.

## 🧪 API foydalanish

API endpointlari orqali quyidagi amallarni bajarish mumkin:

- **Kirimlar**: `GET /api_main/incomes/`, `POST /api_main/incomes/`
- **Chiqimlar**: `GET /api_main/expenses/`, `POST /api_main/expenses/`
- **Foydalanuvchilar**: `GET /api_users/`, `POST /api_users/`

API endpointlari haqida batafsil ma'lumot olish uchun `api_main` va `api_users` ilovalaridagi `views.py` fayllarini ko‘rib chiqing.

## 📄 Litsenziya

Ushbu loyiha [MIT litsenziyasi](LICENSE) asosida tarqatiladi.