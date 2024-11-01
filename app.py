from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
import mysql.connector, os, time
from uuid import uuid4
from mysql.connector import Error
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'DIjhN2ygPe'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.config['UPLOAD_FOLDER'] = 'static/uploads/'  
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

def verify_secretpass(secret_password):
    senha = 'astrotoldos2024!'
    
    if secret_password == senha:
        return True
    
def get_db_connection():
    try:
        connection = mysql.connector.connect(host='localhost',database='astro1',user='root',password='root')
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
    cursor.execute("SELECT id, username FROM user WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    connection.close()
    
    if user:
        return User(user[0], user[1])
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT id, password FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()
        connection.close()
        
        if user and bcrypt.check_password_hash(user[1], password):
            user_obj = User(user[0], email)
            login_user(user_obj)
            flash('Logado com Sucesso', 'success')
            return redirect(url_for('index'))
        else:
            flash('Senha ou Email inválidos', 'danger')
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
                cursor.execute("INSERT INTO user (username, email, password) VALUES (%s, %s, %s)", (name, email, password))
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

@app.route('/nossos-produtos', methods=['GET'])
def nossos_produtos():
    connection = get_db_connection()
    
    if connection:
        try:
            cursor = connection.cursor()
            sql = "SELECT id, nome, descricao, foto_principal_url FROM cano;"
            cursor.execute(sql)
            canos = cursor.fetchall() 
            cursor.close()
        except Error as e:
            print(f"Erro ao consultar dados no banco de dados: {e}")
        finally:
            connection.close()
            
    if current_user.is_authenticated:
        return render_template('produtos_adm.html', canos=canos)
    
    return render_template('produtos.html', canos=canos)


@app.route('/adicionar-tubo', methods=['GET', 'POST'])
def adicionar_cano():
    
    if current_user.is_authenticated:
        if request.method == 'POST':
            nome = request.form.get('nome')
            descricao = request.form.get('descricao')
            foto = request.files['foto']

            if foto:
                timestamp = int(time.time())  
                unique_id = uuid4().hex  
                extension = os.path.splitext(foto.filename)[1]  
                filename = f"{nome}_{timestamp}_{unique_id}{extension}"  
                foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                foto_path_bd = 'uploads/' + filename
                foto.save(foto_path)
            else:
                foto_path = None

            connection = get_db_connection()
            if connection:
                try:
                    cursor = connection.cursor()
                    sql = """
                        INSERT INTO cano (nome, descricao, foto_principal_url)
                        VALUES (%s, %s, %s)
                    """
                    cursor.execute(sql, (nome, descricao, foto_path_bd))
                    connection.commit()
                    cursor.close()
                except Error as e:
                    print(f"Erro ao inserir dados no banco de dados: {e}")
                finally:
                    connection.close()

            return redirect(url_for('nossos_produtos'))
    
    return redirect(url_for('nossos_produtos'))

@app.route('/tubo/<int:cano_id>', methods=['GET'])
def cano(cano_id):
    connection = get_db_connection()
    cano = None
    resultados = []

    if connection:
        try:
            cursor = connection.cursor()
            
            # Consulta para obter as informações do cano
            sql = "SELECT id, nome, descricao, foto_principal_url FROM cano WHERE id = %s;"
            cursor.execute(sql, (cano_id,))
            cano = cursor.fetchone()
            
            # Consulta para obter as bitolas e espessuras associadas ao cano
            cursor.execute("""
                SELECT b.descricao AS bitola,
                       e.valor AS espessura
                FROM bitola b
                LEFT JOIN espessura e ON b.id = e.bitola_id
                WHERE b.cano_id = %s
                ORDER BY b.id;
            """, (cano_id,))
            
            resultados = cursor.fetchall()
            cursor.close()
        except Error as e:
            print(f"Erro ao consultar dados no banco de dados: {e}")
        finally:
            connection.close()
    
    # Renderiza o template adequado com base na autenticação do usuário
    if cano:
        if current_user.is_authenticated:
            print(resultados)
            return render_template('cano_adm.html', cano=cano, resultados=resultados)
        return render_template('cano.html', cano=cano, resultados=resultados)
    else:
        return "Cano não encontrado", 404


@app.errorhandler(404) 
def not_found(e):  
    return render_template("404.html")

if __name__ == "__main__":
    app.run(debug=True) 



