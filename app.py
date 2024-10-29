from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)
app.secret_key = 'DIjhN2ygPe'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


def verify_secretpass(secret_password):
    senha = 'astrotoldos2024'
    
    if secret_password == senha:
        return True
    
def get_db_connection():
    try:
        connection = mysql.connector.connect(host='localhost',database='astro',user='root',password='root')
        return connection
    except Error as e:
        print(f"Error connecting to MySQL Platform: {e}")
        return None

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    connection.close()
    
    if user:
        return User(user[0], user[1])
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        connection.close()
        
        if user and bcrypt.check_password_hash(user[1], password):
            user_obj = User(user[0], username)
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        
        name = request.form['name']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        secret_pass = request.form['secret_password']
        
        connection = get_db_connection()
        cursor = connection.cursor()

        if verify_secretpass(secret_pass):
            try:
                cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (name, email, password))
                connection.commit()
                flash('Conta criada com sucesso', 'success')
                return redirect(url_for('login'))
            except mysql.connector.IntegrityError:
                flash('Nome ou Email já existentes', 'danger')
            finally:
                cursor.close()
                connection.close()
        else:
            flash('Senha secreta inválida', 'danger')
            
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/contato')
def contato():
    return render_template('contact.html')

@app.route('/orçamento')
def orcamento():
    return render_template('quote.html')

@app.route('/nossos-serviços')
def nossos_servicos():
    return render_template('service.html')

@app.errorhandler(404) 
def not_found(e):  
    return render_template("404.html")

if __name__ == "__main__":
    app.run(debug=True) 



