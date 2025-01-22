from bokeh.themes import default

from database import db
from sqlalchemy.sql import func

class Meals(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(30),nullable=False)
    descricao = db.Column(db.String(80), nullable=True)
    date_and_time = db.Column(db.DateTime, nullable=False, default=func.now())
    role_diet = db.Column(db.String(5),nullable=False,default = "sim")
    # Chave estrangeira para a tabela de usuários
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)

    user = db.relationship('User', backref='meals')  # Relacionamento com o modelo Users