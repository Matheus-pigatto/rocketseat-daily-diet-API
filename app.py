from flask import Flask,request,jsonify
from database import db
from models.user import User
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from sqlalchemy import update
import bcrypt


app = Flask(__name__)
app.config['SECRETY_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:admin123@127.0.0.1:3306/flask-crud'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

#view login
login_manager.login_view = 'login'
#session<- conexão ativa


@app.route('/')
def hello_word():
    return "hello Word"




if __name__ == '__main__':
    app.run(debug=True)