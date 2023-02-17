from flask import Flask, render_template, redirect, url_for, flash,request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,RegisterForm,LoginForm,CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort


app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = db.relationship("BlogPost", back_populates="author")
    comments=db.relationship("Comment",back_populates="author")

class BlogPost(UserMixin,db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = db.relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship("Comment", back_populates="post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    text = db.Column(db.Text, nullable=False)
    author=db.relationship("User",back_populates="comments")
    post=db.relationship("BlogPost",back_populates="comments")

    # author = db.relationship("User", back_populates="posts")
    # title = db.Column(db.String(250), unique=True, nullable=False)
    # subtitle = db.Column(db.String(250), nullable=False)
    # date = db.Column(db.String(250), nullable=False)
    # img_url = db.Column(db.String(250), nullable=False)

with app.app_context():
    db.create_all()

# Customer.invoices = relationship("Invoice", order_by = Invoice.id, back_populates = "customer")
# User.blog_posts = relationship("BlogPost", order_by = BlogPost.id, back_populates = "author")

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.is_anonymous:
            return abort(403)
        if current_user.id != 1 :
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def get_all_posts():
    print(current_user)
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,current_user_id=current_user.get_id(),current_user=current_user)

@app.route('/register',methods=['GET','POST'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=request.form['email']).first()
        if user:
            flash('User already registered ,please login instead!')
            return redirect(url_for('login'))
        elif not user:
            new_user = User(
                email=request.form['email'],
                password=generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8),
                name=request.form['name']
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html",form=form,current_user=current_user)

@app.route('/login',methods=['GET', 'POST'])
def login():
    form=LoginForm()
    if request.method == "POST":
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password,request.form['password']):
            login_user(user)
            # flash('Logged in successfully.')
            if current_user.is_authenticated:
                print(True)
            return redirect(url_for('get_all_posts'))
        elif not user:
            flash('User doesnt exist!')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password,request.form['password']):
            flash('Incorrect password!')
            return redirect(url_for('login'))
    return render_template("login.html",form=form,current_user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route("/post/<int:post_id>",methods=['GET','POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if(current_user.is_authenticated):
            new_comment = Comment(
                text=form.comment.data,
                author=current_user,
                post_id = post_id
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash('Please register or login to be able to post a comment.')
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post,current_user=current_user,form=form,current_user_id=current_user.get_id(),comments=Comment.query.all())

@app.route("/about")
def about():
    return render_template("about.html",current_user=current_user)

@app.route("/contact")
def contact():
    return render_template("contact.html",current_user=current_user)

@app.route("/new-post",methods=['GET','POST'])
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
    return render_template("make-post.html", form=form,current_user=current_user)

@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,current_user=current_user)

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
