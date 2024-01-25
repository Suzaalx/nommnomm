from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import os
from sqlalchemy.orm import relationship
from flask_bootstrap import Bootstrap5
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'django-ins'
bootstrap= Bootstrap5(app)

# Set up the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recipes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Set up the login manager
login_manager = LoginManager()
login_manager.init_app(app)

# Create a user loader function takes userid and returns User object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create user model
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(80))
    password = db.Column(db.String(80))
    recipe = relationship("Recipe", back_populates="author")
    comments = relationship("Comment", back_populates="user")

# Create recipe model
class Recipe(db.Model):
    __tablename__ = 'recipes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    subtitle = db.Column(db.Text)
    instructions = db.Column(db.Text, nullable=False)
    cooking_time = db.Column(db.Integer)
    difficulty_level = db.Column(db.String(50))
    image = db.Column(db.String(255))
    ingredients = db.Column(db.String(255))
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="recipe")
    comments = relationship("Comment", back_populates="recipe")
    
class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipes.id'))
    recipe = relationship("Recipe", back_populates="comments")
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship("User", back_populates="comments")




#initialize the database
with app.app_context():
    db.create_all()

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        else:
            flash("You need to be an admin to view this page")
            return redirect(url_for('index'))
    return wrap

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        else:
            flash("You need to be logged in to view this page")
            return redirect(url_for('login'))
    return wrap

def author_required(f):
    @wraps(f)
    def wrap(recipe_id, *args, **kwargs):
        recipe = Recipe.query.get(recipe_id)

        if recipe and current_user.is_authenticated and current_user.id == recipe.author_id:
            return f(recipe_id, *args, **kwargs)
        else:
            flash("You need to be the author to view this page")
            return redirect(url_for('index'))

    return wrap

#route for home page
@app.route('/')
def index():
    return render_template('routes/index.html',current_user=current_user, recipes=Recipe.query.all())

#route for recipe page
@app.route('/recipe/<int:recipe_id>',methods=['GET', 'POST'])
def recipe(recipe_id):
    if request.method == 'POST':
        comment = request.form.get('comment')
        recipe_id = recipe_id
        user_id = current_user.id
        new_comment = Comment(comment=comment, recipe_id=recipe_id, user_id=user_id)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('recipe', recipe_id=recipe_id))
    recipe = Recipe.query.get(recipe_id)
    return render_template('routes/recipe.html',current_user=current_user, recipe=recipe)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('username')
        password = request.form.get('password')

        # Check if email already exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('register'))

        # Create new user with the form data. Hash the password so plaintext version isn't saved.
        new_user = User(email=email, name=name, password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)) 

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('routes/register.html',current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password_input = request.form.get('password')
        #remember = True if request.form.get('remember') else False

        user = User.query.filter_by(email=email).first()

        # Check if the user exists
        # Take the user-supplied password, hash it, and compare it to the hashed password in database
        if not user or not check_password_hash(user.password, password_input):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('index'))
    return render_template('routes/login.html',current_user=current_user)

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = User.query.get(user_id)
    return render_template('routes/profile.html',current_user=current_user, user=user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/new-recipe', methods=['GET', 'POST'])
@login_required
def new_recipe():
    if request.method == 'POST':
        title = request.form.get('title')
        subtitle = request.form.get('subtitle')
        instructions = request.form.get('instructions')
        cooking_time = request.form.get('cooking_time')
        difficulty_level = request.form.get('difficulty_level')
        image = request.form.get('image')
        ingredients = request.form.get('ingredients')
        author_id= current_user.id
        new_recipe = Recipe(title=title, subtitle=subtitle, instructions=instructions, cooking_time=cooking_time, ingredients=ingredients, difficulty_level=difficulty_level, image=image, author_id=author_id)
        db.session.add(new_recipe)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('routes/new_recipe.html',current_user=current_user)

@app.route('/edit_recipe/<int:recipe_id>', methods=['GET', 'POST'])
@login_required
@author_required
def edit_recipe(recipe_id):
    recipe = Recipe.query.get(recipe_id)
    
    if request.method == 'POST':
        recipe.title = request.form.get('title')
        recipe.subtitle = request.form.get('subtitle')
        recipe.instructions = request.form.get('instructions')
        recipe.cooking_time = request.form.get('cooking_time')
        recipe.difficulty_level = request.form.get('difficulty_level')
        recipe.image = request.form.get('image')
        recipe.ingredients = request.form.get('ingredients')
        db.session.commit()
        return redirect(url_for('recipe', recipe_id=recipe_id))
    
    return render_template('routes/edit_recipe.html', current_user=current_user, recipe=recipe)

@app.route('/delete_recipe/<int:recipe_id>', methods=['GET', 'POST'])
@login_required
@author_required
def delete_recipe(recipe_id):
    recipe = Recipe.query.get(recipe_id)
    db.session.delete(recipe)
    db.session.commit()
    return redirect(url_for('index'))







if __name__ == '__main__':
    app.run(debug=True)