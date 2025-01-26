from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy

# Initialize the Flask app and database
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'


db = SQLAlchemy(app)

# Database model
class User(db.Model):  
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)

# Create the database tables
with app.app_context():
    db.create_all()

    
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', password='admin', is_admin=True)
        db.session.add(admin_user)
        db.session.commit()

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        flash('Invalid username or password!')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!')
            return redirect(url_for('signup'))
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password, is_admin=True).first()
        if user:
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin  # Store admin status
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials!')
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' in session and session.get('is_admin', False):
        users = User.query.all()
        return render_template('admin_dashboard.html', users=users)
    flash('Unauthorized access!')
    return redirect(url_for('admin_login'))

@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if not session.get('is_admin'):
        flash('Unauthorized access!')
        return redirect(url_for('admin_login'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!')
            return redirect(url_for('create_user'))
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully!')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_user.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        flash('Unauthorized access!')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        amount = int(request.form['amount'])
        if 'deposit' in request.form:
            user.balance += amount
            flash(f'Deposited {amount} successfully!')
        elif 'withdraw' in request.form:
            if user.balance >= amount:
                user.balance -= amount
                flash(f'Withdrew {amount} successfully!')
            else:
                flash('Insufficient balance!')
        db.session.commit()
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
