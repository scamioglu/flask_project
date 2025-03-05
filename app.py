from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS parents 
                 (id INTEGER PRIMARY KEY, name TEXT, stage INTEGER, data TEXT, pdf_path TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS forms 
                 (id INTEGER PRIMARY KEY, stage INTEGER, question TEXT, type TEXT, options TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", 
              ('admin', generate_password_hash('admin123'), 'admin'))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['role'] = user[3]
            if user[3] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('staff_form'))
        flash('Geçersiz kullanıcı adı veya şifre')
    return render_template('login.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    if request.method == 'POST':
        if 'add_parent' in request.form:
            name = request.form['parent_name']
            c.execute("INSERT INTO parents (name, stage, data, pdf_path) VALUES (?, ?, ?, ?)", 
                      (name, 1, '', ''))
        elif 'add_user' in request.form:
            username = request.form['username']
            password = generate_password_hash(request.form['password'])
            role = request.form['role']
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      (username, password, role))
        elif 'reset_password' in request.form:
            user_id = request.form['user_id']
            new_password = generate_password_hash('123456')
            c.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))
        elif 'add_form' in request.form:
            stage = request.form['stage']
            question = request.form['question']
            form_type = request.form['type']
            options = request.form.get('options', '')
            c.execute("INSERT INTO forms (stage, question, type, options) VALUES (?, ?, ?, ?)", 
                      (stage, question, form_type, options))
        conn.commit()
    
    c.execute("SELECT * FROM users WHERE role != 'admin'")
    users = c.fetchall()
    c.execute("SELECT * FROM parents")
    parents = c.fetchall()
    c.execute("SELECT * FROM forms")
    forms = c.fetchall()
    conn.close()
    return render_template('admin_dashboard.html', users=users, parents=parents, forms=forms)

@app.route('/staff/form', methods=['GET', 'POST'])
def staff_form():
    if 'user_id' not in session or session['role'] == 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    stage = int(session['role'].split('_')[1])
    
    if request.method == 'POST':
        if 'add_parent' in request.form:
            name = request.form['parent_name']
            c.execute("INSERT INTO parents (name, stage, data, pdf_path) VALUES (?, ?, ?, ?)", 
                      (name, stage, '', ''))
        else:
            parent_id = request.form['parent_id']
            data = {}
            for key, value in request.form.items():
                if key.startswith('question_'):
                    data[key] = value
            pdf = request.files.get('pdf')
            pdf_path = f"uploads/{pdf.filename}" if pdf else None
            if pdf:
                pdf.save(pdf_path)
            c.execute("UPDATE parents SET stage = ?, data = ?, pdf_path = ? WHERE id = ?", 
                      (stage + 1 if stage < 4 else 4, str(data), pdf_path, parent_id))
        conn.commit()
        flash('Kaydedildi!')
    
    c.execute("SELECT * FROM parents WHERE stage <= ?", (stage,))
    parents = c.fetchall()
    c.execute("SELECT * FROM forms WHERE stage = ?", (stage,))
    forms = c.fetchall()
    conn.close()
    return render_template('staff_form.html', parents=parents, stage=stage, forms=forms)

@app.route('/report')
def report():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM parents")
    parents = c.fetchall()
    conn.close()
    return render_template('report.html', parents=parents)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    init_db()
    app.run(debug=True, host='0.0.0.0')