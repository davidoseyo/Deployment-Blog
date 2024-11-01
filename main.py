import os
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, user_login_confirmed, \
    login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)



#Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user_database_table.id"))

    # Create reference to the User object. The "posts" refers to the posts property in the User class.
    author : Mapped["User"] = relationship('User', back_populates="posts")
    comments = relationship("Comment", back_populates="comment_post")


# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = 'user_database_table'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


# TODO: Create a comment table for all users.
class Comment(db.Model):
    __tablename__ = 'comments'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user_database_table.id"))
    comment_author = relationship("User", back_populates="comments")

    # Create reference to the User object. The "posts" refers to the posts property in the User class.

    post_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    comment_post: Mapped["User"] = relationship('BlogPost', back_populates="comments")



with app.app_context():
    db.create_all()


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# TODO: Use Werkzeug to hash the user's password when creating a new user.

@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(
            request.form.get("password"),
            method='scrypt',
            salt_length=16
        )

        email_field = request.form.get('email_field')
        name = request.form.get('name')


        user_auth = db.session.execute(db.select(User).where(User.email == form.email_field.data)).scalar()

        if user_auth:
            flash("You've already Signed up with that email, log in instead!")
            return redirect(url_for("login"))

        else:
            new_user = User(
                email=request.form.get('email_field'),
                password=hashed_password,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for("get_all_posts", logged_out=False))
    return render_template("register.html", form=form, current_user=current_user)


# TODO: Retrieve a user from the database based on their email.

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user_auth = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()

        if user_auth and check_password_hash(user_auth.password, form.password.data):
            login_user(user_auth)
            return redirect(url_for('get_all_posts', logged_out=False))

        elif not user_auth:
            flash("Email does not exist, Please try again.")
            return redirect(url_for('login'))

        else:
            flash("Password incorrect, Please try again.")
            return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):

    requested_post = db.get_or_404(BlogPost, post_id)
    # Add the CommentForm to the route
    comment_form = CommentForm()

    comment = db.session.execute(db.select(Comment))
    comment_post = comment.scalars().all()

    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            comment = Comment(
                text=comment_form.comment.data,
                author_id=current_user.id,
                post_id=post_id

            )

            db.session.add(comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, current_user=current_user,
                                   form=comment_form)

        else:
            flash("You need to login or register to comment.")
            return redirect(url_for('login'))

    else:
        return render_template("post.html", post=requested_post, current_user=current_user,
                               form=comment_form)




# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False)
