
from turtle import pos
from flask import Flask, redirect, render_template, url_for, flash, request
from matplotlib.pyplot import title
from matplotlib.style import use
from requests import session
import sqlalchemy
from forms import UserForm, PasswordTestForm, PostForm, LoginForm, SearchForm
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_ckeditor import CKEditor
from werkzeug.utils import secure_filename

app = Flask(__name__)
ckeditor = CKEditor(app)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://joaugmfoldlisw:918276dd69d3e6104af5e3122153bda1145101947b11da1e8a41df4a10b1e517@ec2-23-23-182-238.compute-1.amazonaws.com:5432/d7a6oafl7uderj'
app.config['SECRET_KEY'] = "e07e5ecdb25b94b71947500f166ce38e"

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Login stuff

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text())
    author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    slug = db.Column(db.String(255))
    # Foreign key
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(128))
    favorite_anime = db.Column(db.String(120))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    # User can have many posts
    posts = db.relationship('Posts', backref='poster')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return '<Name %r>' % self.name


@app.route("/")
@app.route("/home")
def home():
    anime_list = ["Attack on Titan", "Steins;Gate", "Fate Series"]
    return render_template('index.html', anime_list=anime_list)


@app.route('/userprofile', methods=["GET", "POST"])
def userprofile():
    name = None
    form = UserForm()
    website_users = Users.query.order_by(Users.date_added)
    return render_template("user.html", username=name, form=form, website_users=website_users)


@app.route('/users/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email_id.data).first()
        if user is None:
            hashed_pw = generate_password_hash(
                form.password_hash.data, "sha256")
            user = Users(name=form.username.data,
                         email=form.email_id.data, password_hash=hashed_pw, favorite_anime=form.favorite_anime.data)
            db.session.add(user)
            db.session.commit()
        name = form.username.data
        form.username.data = ''
        form.email_id.data = ''
        form.password_hash.data = ''
        form.password_hash2.data = ''
        form.favorite_anime.data = ''
        flash('User added successfully!')
    website_users = Users.query.order_by(Users.date_added)
    return render_template('add_users.html', form=form, username=name, website_users=website_users)


@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_user(id):
    form = UserForm()
    hashed_pw = None
    user_to_update = Users.query.get_or_404(id)

    if request.method == 'POST':
        user_to_update.name = request.form['username']
        user_to_update.email = request.form['email_id']
        hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
        user_to_update.password_hash = hashed_pw
        user_to_update.favorite_anime = request.form['favorite_anime']
        try:
            db.session.commit()
            flash("User updated successfully!")
            return render_template('update_user.html', form=form, user_to_update=user_to_update, id=id)
        except:
            flash("Couldn't update, there was a problem :(")
            return render_template('update_user.html', form=form, user_to_update=user_to_update, id=id)
    else:
        return render_template('update_user.html', form=form, user_to_update=user_to_update, id=id)


@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def delete_user(id):
    form = UserForm()
    user_to_delete = Users.query.get_or_404(id)
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User deleted successfully!!")
        website_users = Users.query.order_by(Users.date_added)
        return render_template('user.html', form=form, website_users=website_users, id=id)
    except:
        flash("Error deleting user :( ")
        website_users = Users.query.order_by(Users.date_added)
        return render_template('user.html', form=form, website_users=website_users, id=id)


@app.route('/search_user', methods=['GET', 'POST'])
def search_user():
    form = UserForm()
    username = None

    if request.method == 'POST':
        username = form.username.data
        user_to_search = Users.query.filter_by(name=username)
        if user_to_search != None:

            return render_template('search_user.html', form=form, user_to_search=user_to_search)
            return redirect('/userprofile')

        else:
            flash("User not found :(")
            website_users = Users.query.order_by(Users.date_added)
            return render_template('user.html', form=form, website_users=website_users, username=username)

    else:
        website_users = Users.query.order_by(Users.date_added)
        return render_template('search_user.html', form=form, website_users=website_users)


@app.route('/pw_test', methods=['GET', 'POST'])
def pw_test():
    form = PasswordTestForm()
    email = None
    password = None
    user_to_check = None
    passed = None
    if form.validate_on_submit():
        email = form.email_id.data
        password = form.password_hash.data
        form.email_id.data = ''
        form.password_hash.data = ''
        user_to_check = Users.query.filter_by(email=email).first()
        passed = check_password_hash(user_to_check.password_hash, password)

        flash("Details submitted successfully!")
    return render_template('pw_test.html', email=email, password=password, passed=passed, user_to_check=user_to_check, form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(name=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password_hash.data):
                login_user(user)
                flash('Login Successful!')
                return redirect(url_for('dashboard'))
            else:
                flash('Wrong password :( Try again!!')
        else:
            flash("User doesn't exist!! (yet, but you can change that! ;))")
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("Logged out! You can no longer see your dashboard T__T")
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    poster = current_user.id
    if current_user.is_authenticated:
        form.author.data = current_user.name
    if form.validate_on_submit():
        post = Posts(title=form.title.data, author=current_user.name, poster_id=poster,
                     content=form.content.data, slug=form.slug.data)
        form.title.data = ''
        form.content.data = ''
        form.slug.data = ''

        db.session.add(post)
        db.session.commit()

        flash("Post added succesfully!!")
    return render_template('add_post.html', form=form)


@app.route('/posts')
def posts():
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template('posts.html', posts=posts)


@app.route('/posts/<int:id>')
def post(id):
    post = Posts.query.get_or_404(id)
    return render_template('post.html', post=post)


@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        post.slug = form.slug.data

        db.session.add(post)
        db.session.commit()

        flash('Post updated successfully!!')
        return redirect(url_for('post', id=post.id))

    if current_user.id == post.poster.id:

        form.title.data = post.title
        form.content.data = post.content
        form.slug.data = post.slug

        return render_template('edit_post.html', form=form, post=post)
    else:
        flash("You cannot edit someone else's post! >__<")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template('posts.html', posts=posts)


@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    id = current_user.id
    if id == post_to_delete.poster.id:
        try:
            db.session.delete(post_to_delete)
            db.session.commit()

            flash('Post deleted successfully!')
            posts = Posts.query.order_by(Posts.date_posted)
            return render_template('posts.html', posts=posts)
        except:
            flash("Oops! Couldn't delete post, there was a problem! :(")
            posts = Posts.query.order_by(Posts.date_posted)
            return render_template('posts.html', posts=posts)

    flash("You cannot delete someone else's post! >__<")
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template('posts.html', posts=posts)


@app.context_processor
def base():
    form = SearchForm()
    return dict(form=form)


@app.route('/search', methods=['POST'])
def search():
    form = SearchForm()
    posts = Posts.query
    if form.validate_on_submit():
        post.searched = form.searched.data
        posts = posts.filter(Posts.content.like('%' + post.searched + '%'))
        posts = posts.order_by(Posts.title).all()
        return render_template('search.html', searched=post.searched, form=form, posts=posts)


@app.route('/admin')
@login_required
def admin():
    id = current_user.id
    if id == 1:
        return render_template('admin.html')
    else:
        flash('Only admins can access this page! :(')
        return redirect(url_for('dashboard'))
