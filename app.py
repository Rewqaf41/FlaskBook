from werkzeug.urls import url_parse
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, url_for, redirect, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_login import UserMixin, current_user, login_user, logout_user, login_required
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'you-will-never-guess'
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:Rewqaf223377@localhost:5432/Book"
db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'
migrate = Migrate(app, db)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    books = db.relationship('Book', backref='person', lazy=True)

    def __int__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    author = db.Column(db.String(50), nullable=False)
    pages = db.Column(db.Integer)
    annum = db.Column(db.Integer)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Book %r>' % self.id


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Войти')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')


@app.route('/')
def index():
    return render_template("index.html")


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            # flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/create-add', methods=["POST", "GET"])
def create_add():
    if request.method == "POST":
        author = request.form["author"]
        title = request.form["title"]
        pages = request.form["pages"]
        annum = request.form["annum"]

        book = Book(author=author, title=title, pages=pages, annum=annum)

        try:
            db.session.add(book)
            db.session.commit()
            return redirect('/books')
        except:
            return "Произошла ошибка, книга не добавлена"
    else:
        return render_template("create-add.html")


@app.route('/books')
def books():
    articles = Book.query.order_by(Book.author).all()
    return render_template("books.html", articles=articles)


@app.route('/books/<int:id>/del')
def book_del(id):
    article = Book.query.get_or_404(id)

    try:
        db.session.delete(article)
        db.session.commit()
        return redirect('/books')
    except:
        return 'Error'


@app.route('/books/<int:id>/update', methods=["POST", "GET"])
def book_update(id):
    article = Book.query.get(id)
    if request.method == "POST":
        article.author = request.form["author"]
        article.title = request.form["title"]
        article.pages = request.form["pages"]
        article.annum = request.form["annum"]

        try:
            db.session.commit()
            return redirect('/books')
        except:
            return "Error"
    else:
        return render_template("book_update.html", article=article)


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)


# CRUD (Create read update delete)