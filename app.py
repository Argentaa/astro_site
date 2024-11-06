from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
import mysql.connector, os, time
from uuid import uuid4
from mysql.connector import Error
from werkzeug.utils import secure_filename
from collections import defaultdict

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

    return render_template('index.html', canos=canos)

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

@login_required
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
            
            sql = "SELECT id, nome, descricao, foto_principal_url FROM cano WHERE id = %s;"
            cursor.execute(sql, (cano_id,))
            cano = cursor.fetchone()

            cursor.execute("""
                SELECT 
                    b.id AS bitola_id,
                    b.descricao AS bitola,
                    GROUP_CONCAT(e.id ORDER BY e.valor SEPARATOR ', ') AS espessura_ids,
                    GROUP_CONCAT(e.valor ORDER BY e.valor SEPARATOR ', ') AS espessuras
                FROM 
                    bitola b
                LEFT JOIN 
                    espessura e ON b.id = e.bitola_id
                WHERE 
                    b.cano_id = %s
                GROUP BY 
                    b.id
                ORDER BY 
                    b.id;
                            """, (cano_id,))


            resultados = cursor.fetchall()
            
            resultados_formatados = [
                    {
                        'bitola_id': bitola_id,
                        'bitola': bitola,
                        'espessuras': [float(valor.strip()) for valor in espessuras.split(',')] if espessura_ids else [],
                        'espessura_ids': [int(esp_id.strip()) for esp_id in espessura_ids.split(',')] if espessura_ids else [],
                        'espessuras_com_ids': list(zip(
                            [float(valor.strip()) for valor in espessuras.split(',')] if espessura_ids else [],
                            [int(esp_id.strip()) for esp_id in espessura_ids.split(',')] if espessura_ids else []
                        ))
                    }
                    for bitola_id, bitola, espessura_ids, espessuras in resultados
                ]
            
            cursor.execute(""" SELECT * FROM cano_fotos WHERE cano_id = %s""", (cano_id,))
            fotos_canos = cursor.fetchall()
            print(fotos_canos)
            
        except Error as e:
            print(f"Erro ao consultar dados no banco de dados: {e}")
        finally:
            connection.close()
    
    if cano:
        if current_user.is_authenticated:
            return render_template('cano_adm.html', cano=cano, resultados=resultados_formatados, fotos_cano=fotos_canos)
        return render_template('cano.html', cano=cano, resultados=resultados_formatados, fotos_cano=fotos_canos)
    else:
        return "Cano não encontrado", 404

@login_required
@app.route('/edit_caracteristicas/<int:cano_id>', methods=['GET', 'POST'])
def edit_caracteristicas(cano_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        for key, value in request.form.items():
            print(f'key: {key}, value: {value}')

        for key, value in request.form.items():
            if key.startswith('bitola_'):
                try:
                    bitola_id = int(key.split('_')[1])  # Extrair o ID da bitola
                    descricao = value.strip()

                    if descricao:  # Se a descrição não está em branco, atualiza
                        cursor.execute("UPDATE bitola SET descricao = %s WHERE id = %s", (descricao, bitola_id))
                    else:  # Se está em branco, apaga a bitola
                        cursor.execute("DELETE FROM bitola WHERE id = %s", (bitola_id,))

                except (ValueError, IndexError):
                    print(f"Valor inválido para bitola_id: {key.split('_')[1]}")
                    continue

            elif key.startswith('espessura_'):
                try:
                    espessura_id = int(key.split('_')[1])  # Extrair o ID da espessura
                    esp_valor = value.strip()

                    if esp_valor:  # Se o valor da espessura não está em branco, atualiza
                        cursor.execute("UPDATE espessura SET valor = %s WHERE id = %s", (float(esp_valor), espessura_id))
                    else:  # Se está em branco, apaga a espessura
                        cursor.execute("DELETE FROM espessura WHERE id = %s", (espessura_id,))

                except (ValueError, IndexError):
                    print(f"Valor inválido para espessura: {value}")
                    continue

            elif key.startswith('nova_bitola_'):
                try:
                    nova_descricao = value.strip()
                    if nova_descricao:  # Só insere uma nova bitola se tiver descrição
                        cursor.execute("INSERT INTO bitola (cano_id, descricao) VALUES (%s, %s)", (cano_id, nova_descricao))
                        nova_bitola_id = cursor.lastrowid  # Captura o ID da nova bitola inserida

                        # Inserir espessuras associadas à nova bitola
                        for esp_key, esp_value in request.form.items():
                            # Verifica se o campo de espessura pertence a essa nova bitola
                            if esp_key.startswith(f'nova_espessura_{key.split("_")[2]}_'):
                                esp_valor = esp_value.strip()
                                if esp_valor:  # Só insere se o valor da espessura não estiver em branco
                                    cursor.execute("INSERT INTO espessura (bitola_id, valor) VALUES (%s, %s)", (nova_bitola_id, float(esp_valor)))

                except (ValueError, IndexError):
                    print(f"Valor inválido para nova bitola: {value}")
                    continue

            elif key.startswith('nova_espessura_'):
                try:
                    nova_bitola_id = int(key.split('_')[2])  # Extrair o ID da bitola associada
                    cursor.execute("SELECT id FROM bitola WHERE id = %s", (nova_bitola_id,))
                    if cursor.fetchone() is None:
                        print(f"Bitola ID {nova_bitola_id} não encontrada para nova espessura.")
                        continue
                    
                    esp_valor = value.strip()
                    if esp_valor:  # Só insere se o valor da espessura não estiver em branco
                        cursor.execute("INSERT INTO espessura (bitola_id, valor) VALUES (%s, %s)", (nova_bitola_id, float(esp_valor)))

                except (ValueError, IndexError):
                    print(f"Valor inválido para nova espessura: {value}")
                    continue

        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('cano', cano_id=cano_id))

@login_required
@app.route('/editar/<int:id>', methods=['POST'])
def editar_cano(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        # Atualizar informações do `cano`
        nome = request.form['titulo']
        descricao = request.form['texto']
        
        # Atualizar o campo `foto_principal` se uma nova imagem foi enviada
        foto_principal = request.files.get('foto_principal')
        
        if foto_principal and foto_principal.filename != '':
            timestamp = int(time.time())  
            unique_id = uuid4().hex  
            extension = os.path.splitext(foto_principal.filename)[1]
            filename = f"{nome}_{timestamp}_{unique_id}{extension}"
            foto_principal_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            foto_principal_path_bd = 'uploads/' + filename
            
            foto_principal.save(foto_principal_path)

            # Obter o caminho atual da foto principal para deletar o arquivo antigo
            cursor.execute("SELECT foto_principal_url FROM cano WHERE id = %s", (id,))
            old_foto_principal = cursor.fetchone()
            if old_foto_principal and old_foto_principal[0]:  # Verifica se o resultado não é None e se há uma URL
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], old_foto_principal[0][8:]))

            # Atualizar o caminho da foto principal no banco
            cursor.execute("UPDATE cano SET nome = %s, descricao = %s, foto_principal_url = %s WHERE id = %s",
                           (nome, descricao, foto_principal_path_bd, id))
        else:
            # Apenas atualizar nome e descrição se nenhuma nova foto principal for enviada
            cursor.execute("UPDATE cano SET nome = %s, descricao = %s WHERE id = %s", (nome, descricao, id))

        # Gerenciar fotos adicionais para `cano`
        novas_fotos = request.files.getlist('nova_foto')
        for foto in novas_fotos:
            if foto.filename != '':
                timestamp = int(time.time())  
                unique_id = uuid4().hex  
                extension = os.path.splitext(foto.filename)[1]
                filename = f"{nome}_{timestamp}_{unique_id}{extension}"
                foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                foto_path_bd = 'uploads/' + filename
                
                foto.save(foto_path)
                cursor.execute("INSERT INTO cano_fotos (cano_id, foto_url) VALUES (%s, %s)", (id, foto_path_bd))

        # Excluir fotos adicionais marcadas para remoção
        fotos_a_excluir = request.form.getlist('fotos_a_excluir')[0].split(",")
        for foto_id in fotos_a_excluir:
            if foto_id:
                cursor.execute("SELECT foto_url FROM cano_fotos WHERE id = %s", (foto_id,))
                caminho_foto = cursor.fetchone()
                if caminho_foto and caminho_foto[0]:  # Verifica se o caminho da foto existe
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], caminho_foto[0][8:]))
                    cursor.execute("DELETE FROM cano_fotos WHERE id = %s", (foto_id,))
    
    conn.commit()
    cursor.close()
    conn.close()

    return redirect(url_for('cano', cano_id=id))

@app.errorhandler(404) 
def not_found(e):  
    return render_template("404.html")

if __name__ == "__main__":
    app.run(debug=True) 



