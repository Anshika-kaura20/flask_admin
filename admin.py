from flask import Flask, app, render_template, request, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_manager, login_user, login_required,current_user,logout_user
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView


app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tmp/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'kurukshetra'

db = SQLAlchemy(app)

admin = Admin(app,name='Control Panel')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Users(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(253))
    email = db.Column(db.String(255))
    address = db.Column(db.String(255))
    password = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    

class Controller(ModelView):
    def is_accessible(self):
        if current_user.is_admin == True:
            return current_user.is_authenticated
        else:
            return abort(404)
        # return current_user().is_authenticated
    def not_auth(self):
        return "You are not authorized to use the admin dashboard"

# admin.add_view(ModelView(Users, db.session))

admin.add_view(Controller(Users, db.session))

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process',methods=['POST'])
def process():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    address = request.form['address']
    new_user = Users(name=name, email=email, password=password, address=address)
    db.session.add(new_user)
    db.session.commit()
    return "Welcome sign up!!"

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Users.query.filter_by(email=email).first()
        if user:
            if user.password == password:
                # return "welcome  " + user.name +"!"
                login_user(user)
                return redirect(url_for('dashboard'))
        else:
            return "Invalid email or password"
    return render_template("login.html")

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/unprotect')
def unprotect():
    return"This page is Unprotect!"

@app.route('/table')
@login_required
def table():
    users = Users.query.all()
    return render_template('table.html', users=users)

@app.route('/create_admin' , methods=['GET','POST'])
def create_admin():
    if request.method == 'POST':
        new_user = Users(email=request.form['email'],password=request.form['password'], is_admin=True)
        db.session.add(new_user)
        db.session.commit()
        return "You have create an admin account!!"
    return render_template('admin_signup.html')

@app.route('/logout')
def logout():
    logout_user()
    return "You have logged out!!      <a href='/'>Click here to go to HomePage</a>"



if __name__ == "__main__":
    app.run(debug=True)