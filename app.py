from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
import os
from datetime import datetime
from dotenv import load_dotenv
from groq import Groq
from langchain.chains import ConversationChain
from langchain.memory import ConversationBufferWindowMemory
from langchain_groq import ChatGroq
from pydantic import BaseModel

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", 'your_secret_key')

groq_api_key = os.environ.get('GROQ_API_KEY')

DATABASE = 'users.db'

class GroqConversationModel(BaseModel):
    llm: ChatGroq
    memory: ConversationBufferWindowMemory

    class Config:
        arbitrary_types_allowed = True

def init_db():
    conn = get_db_connection()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                human TEXT,
                AI TEXT,
                timestamp TEXT
            )
        ''')
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def user_exists(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user

def insert_user(username, password):
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()
    return True

def insert_chat_message(username, human, ai_response, timestamp):
    conn = get_db_connection()
    conn.execute("INSERT INTO chat_history (username, human, AI, timestamp) VALUES (?, ?, ?, ?)",
                 (username, human, ai_response, timestamp))
    conn.commit()
    conn.close()

def clear_chat_history(username):
    conn = get_db_connection()
    conn.execute("DELETE FROM chat_history WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def clear_users_table():
    conn = get_db_connection()
    conn.execute("DELETE FROM users")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = user_exists(username)

        if user and user['password'] == password:
            session['logged_in'] = True
            session['username'] = username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Incorrect username or password!', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if insert_user(username, password):
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists!', 'warning')
    return render_template('signup.html')

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    if request.method == 'POST':
        if 'clear_chat' in request.form:
            clear_chat_history(username)
            flash("Chat history cleared!", "success")
        elif 'logout' in request.form:
            session.clear()
            flash('Logged out successfully!', 'info')
            return redirect(url_for('login'))
        else:
            user_question = request.form.get('question')
            if user_question:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                memory = ConversationBufferWindowMemory(k=5)
                groq_chat = ChatGroq(groq_api_key=groq_api_key, model_name='mixtral-8x7b-32768')
                conversation = ConversationChain(llm=groq_chat, memory=memory)
                response = conversation.run(user_question)

                insert_chat_message(username, user_question, response, timestamp)

    conn = get_db_connection()
    db_chat_history = conn.execute("SELECT human, AI, timestamp FROM chat_history WHERE username = ? ORDER BY id DESC", 
                                   (username,)).fetchall()
    conn.close()

    chat_history = [{'human': row['human'], 'AI': row['AI'], 'timestamp': row['timestamp']} for row in db_chat_history]

    return render_template('chat.html', username=username, chat_history=chat_history)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
