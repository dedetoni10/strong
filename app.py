from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "✅ Aplikasi berhasil jalan di Render!"
