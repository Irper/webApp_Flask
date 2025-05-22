from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from cryptography.fernet import Fernet
from sqlalchemy.exc import IntegrityError
import os
import ssl


load_dotenv()  # Загружает переменные из .env
# Конфигурация
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securecards.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 минут

# Инициализация расширений
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Генерация ключа для шифрования
key = os.getenv('ENCRYPTION_KEY').encode() # Получаем ключ из переменных окружения

if not key:
    print("Внимание! Используется временный ключ шифрования. Для production задайте ENCRYPTION_KEY")
    key = Fernet.generate_key()

cipher_suite = Fernet(key)


# Модели базы данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    cards = db.relationship('BankCard', backref='owner', lazy=True)


class BankCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_number_encrypted = db.Column(db.LargeBinary, nullable=False)
    card_holder_encrypted = db.Column(db.LargeBinary, nullable=False)
    expiry_date_encrypted = db.Column(db.LargeBinary, nullable=False)
    cvv_encrypted = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def get_card_number(self):
        try:
            return cipher_suite.decrypt(self.card_number_encrypted).decode()
        except:
            return "Невозможно расшифровать данные карты"

    def get_card_holder(self):
        try:
            return cipher_suite.decrypt(self.card_holder_encrypted).decode()
        except:
            return "Невозможно расшифровать данные"

    def get_expiry_date(self):
        try:
            return cipher_suite.decrypt(self.expiry_date_encrypted).decode()
        except:
            return "Невозможно расшифровать дату"

    def get_cvv(self):
        try:
            return cipher_suite.decrypt(self.cvv_encrypted).decode()
        except:
            return "***"


# Формы
class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя',
                           validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Пароль',
                             validators=[DataRequired(), Length(min=3)])
    confirm_password = PasswordField('Подтвердите пароль',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')


class CardForm(FlaskForm):
    card_number = StringField('Номер карты', validators=[DataRequired(), Length(min=16, max=19)])
    card_holder = StringField('Имя владельца', validators=[DataRequired()])
    expiry_date = StringField('Срок действия (MM/YY)', validators=[DataRequired()])
    cvv = StringField('CVV', validators=[DataRequired(), Length(min=3, max=4)])
    submit = SubmitField('Сохранить')


# Загрузчик пользователя
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Маршруты
@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Неверное имя пользователя или пароль')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Проверяем, существует ли уже пользователь с таким именем
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Пользователь с таким именем уже существует', 'error')
            return redirect(url_for('register'))

        try:
            hashed_password = generate_password_hash(form.password.data)
            user = User(username=form.username.data, password_hash=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Произошла ошибка при регистрации', 'error')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    cards = BankCard.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', cards=cards)


@app.route('/add_card', methods=['GET', 'POST'])
@login_required
def add_card():
    form = CardForm()
    if form.validate_on_submit():
        # Шифрование данных карты перед сохранением в БД
        card = BankCard(
            card_number_encrypted=cipher_suite.encrypt(form.card_number.data.encode()),
            card_holder_encrypted=cipher_suite.encrypt(form.card_holder.data.encode()),
            expiry_date_encrypted=cipher_suite.encrypt(form.expiry_date.data.encode()),
            cvv_encrypted=cipher_suite.encrypt(form.cvv.data.encode()),
            user_id=current_user.id
        )
        db.session.add(card)
        db.session.commit()
        flash('Карта успешно добавлена')
        return redirect(url_for('dashboard'))
    return render_template('add_card.html', form=form)


@app.route('/delete_card/<int:card_id>', methods=['POST'])
@login_required
def delete_card(card_id):
    card = BankCard.query.get_or_404(card_id)
    if card.user_id != current_user.id:
        abort(403)  # Запрещаем удалять чужие карты
    db.session.delete(card)
    db.session.commit()
    flash('Карта успешно удалена')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Защищенные заголовки
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
    return response


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Запуск с SSL в development (для production используйте Nginx + Gunicorn)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Современная версия
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Минимальная версия TLS
    context.load_cert_chain('cert.pem', 'key.pem')  # Замените на свои сертификаты
    app.run(ssl_context=context, host='0.0.0.0', port=5000)