from flask import Flask, request, session, url_for, render_template, redirect, flash, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Response

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Thisisasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#creating model table for the login users
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(40), unique=True)
    password = db.Column(db.String(60))
    contacts = db.relationship("Contact", backref='owner', lazy='dynamic')

#creating model table for the contact
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(50))
    location = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, name, email, phone, location, user_id):
        self.name = name
        self.email = email
        self.phone = phone
        self.location = location
        self.user_id = user_id

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(),
                            Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(),
                                Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(),
                            Length(min=4, max=15)])
    email = StringField('email', validators=[InputRequired(),
                            Email(message='Invalid email'),Length(max=50)])
    password = PasswordField('password', validators=[InputRequired(),
                                Length(min=8, max=50)])



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect Password')
        else:
            flash('Incorrect Username')
    return render_template('login.html', form = form)

@app.route('/signup', methods=['GET','POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username = form.username.data,
                        email = form.email.data,
                        password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('You were Successfully registered')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

#This is the dashboard route where we are going to query on all our Contact data
@app.route('/dashboard')
@login_required
def dashboard():
    contacts = current_user.contacts.all()
    return render_template('dashboard.html', contacts=contacts)

#this route is for inserting data to mysql database via html forms
@app.route('/insert', methods = ['POST'])
@login_required
def insert():
    print(session)
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    location = request.form['location']

    my_data = Contact(name, email, phone, location, user_id = current_user.id)
    db.session.add(my_data)
    db.session.commit()

    flash("Contact added successfully")

    return redirect(url_for('dashboard'))

#this is our update route where we are going to update our contact
@app.route('/update', methods = ['POST'])
@login_required
def update():
    my_data = Contact.query.get(request.form.get('id'))

    my_data.name = request.form['name']
    my_data.email = request.form['email']
    my_data.phone = request.form['phone']
    my_data.location = request.form['location']

    db.session.commit()
    flash("Contact Updated Successfully")

    return redirect(url_for('dashboard'))

#This route is for deleting our contact
@app.route('/delete/<id>/', methods = ['GET', 'POST'])
@login_required
def delete(id):
    my_data = Contact.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
    flash("Contact Deleted Successfully")

    return redirect(url_for('dashboard'))

@app.route('/download')
@login_required
def download():
    contacts = current_user.contacts.all()
    csv=[]
    csv_headers = '{},{},{},{}\n'.format('name','phone','email','location')
    csv.append(csv_headers)
    for i in contacts:
        csv.append('{},{},{},{}\n'.format(str(i.name),str(i.phone),str(i.email),str(i.location)))
    csv = ''.join(csv)
    return Response(
        csv,
        mimetype="text/csv",
        headers={"Content-disposition":
                 "attachment; filename=contact_data.csv"})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
