from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from mysql.connector import Error
import bcrypt

app = Flask(__name__)
app.config.from_object('config.Config')

# MySQL connection settings
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'sambhav1',
    'database': 'flask_app'
}

# Establish MySQL connection
def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        if conn.is_connected():
            return conn
    except Error as e:
        print(f"Error: '{e}'")
    return None

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
                           (first_name, last_name, email, hashed_password.decode('utf-8')))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        else:
            return "Database connection failed!"
    
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            conn.close()

            if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
                session['loggedin'] = True
                session['id'] = user['id']
                session['email'] = user['email']
                return redirect(url_for('home'))
            else:
                return "Incorrect email or password!"
        else:
            return "Database connection failed!"
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('email', None)
    return redirect(url_for('login'))

# Users route (show registered users and allow deletion)
@app.route('/users')
def users():
    if 'loggedin' in session:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users")
            users = cursor.fetchall()
            conn.close()
            return render_template('users.html', users=users)
        else:
            return "Database connection failed!"
    return redirect(url_for('login'))

# Add User route (only accessible when logged in)
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'loggedin' in session:
        if request.method == 'POST':
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            password = request.form['password']
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
                               (first_name, last_name, email, hashed_password.decode('utf-8')))
                conn.commit()
                conn.close()
                return redirect(url_for('users'))  # Redirect to the users list after adding a new user
            else:
                return "Database connection failed!"
        
        return render_template('add_user.html')  # Render the Add User form with link to check users
    return redirect(url_for('login'))


# Delete user route
@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    if 'loggedin' in session:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = %s", (id,))
            conn.commit()
            conn.close()
            return redirect(url_for('users'))
        else:
            return "Database connection failed!"
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
