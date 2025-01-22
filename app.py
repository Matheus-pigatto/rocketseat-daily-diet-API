from collections import OrderedDict

from flask import Flask,request,jsonify
from database import db
from models.user import User
from models.meals import Meals
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from sqlalchemy import update
from datetime import date, datetime
import pytz
import bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:admin123@127.0.0.1:3306/flask-crud'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

#view login
login_manager.login_view = 'login'
#session<- conexão ativa
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

@app.route('/user', methods=["POST"])
def create_user():
    #captura os dados json
    data = request.json

    #captura do campo json
    username = data.get("username")
    password = data.get("password")
    nome = data.get("nome")
    sobrenome = data.get("sobrenome")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password),bcrypt.gensalt())
        user = User(
            username=username,
            password=hashed_password,
            nome=nome,
            sobrenome=sobrenome,
            role='user'
        )
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso"})

    return jsonify({"message":"Dados inválidos"}), 400

@app.route('/login', methods=["POST"])
def login():
    #captura de dados json
    data= request.json

    #captura  do campo json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        #Login
        user = User.query.filter_by(username=username).first()

        if user is None:
            # Usuário não encontrado
            return jsonify({"message": "Usuário incorreto"}), 400

        if not bcrypt.checkpw(str.encode(password), user.password.encode()):
            # Senha incorreta
            return jsonify({"message": "Senha incorreta"}), 406

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticação realizada com sucesso"})

    # Falta de dados no corpo da requisição
    return jsonify({"message": "Dados inválidos"}), 400

@app.route('/logout' , methods=["GET"])
@login_required #proteção para rota, somente é possível dar logout da aplicação se estiver logado
def logout():
    username = current_user.username #referencia o usuário logado
    logout_user() #finaliza a sessão do usuário
    return jsonify({"message":f"Usuário {username} desconectado"})

@app.route('/user/update', methods=["PUT"])
@login_required
def update_user():
    #Pega as informações do json
    data = request.json

    #verifica se o foi fornecido id_user
    target_user_id = data.get("id_user")

    if target_user_id:
        #se foi fornecido id_user então ele deve ter a atribuição de admin
        if current_user.role != "admin":
            return jsonify({"message": "Usuário não autorizado."}),401

        # Busca o usuário alvo no banco de dados
        user = User.query.get(target_user_id)
        if not user:
            return jsonify({"message": "Usuário não encontrado."}), 404

    else:
        #caso não seja o usuário master, então o usuário esta atualizar ele mesmo
        user=current_user

    #pega a atualização dos campos no json
    nome = data.get("nome")
    sobrenome = data.get("sobrenome")
    password = data.get("password")

    hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())

    db.session.execute(
        update(User).where(User.id == current_user.id).values(
            nome=nome,
            sobrenome=sobrenome,
            password=hashed_password
        )
    )
    db.session.commit()
    return jsonify({"message": "Usuário atualizado com sucesso"})

@app.route('/user/<int:user_id>', methods=["DELETE"])
@login_required
def delete_user(user_id):
    user = db.session.get(User, user_id)

    if not user:
        return jsonify({"error": "Usuário não encontrado"}), 404

    if current_user.role != 'admin' or user_id != current_user.id:
        return jsonify({"message": "Operação não permitida"}), 403

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": f"Usuário {user_id} deletado com sucesso" })

@app.route('/meals', methods=["POST"])
@login_required
def create_meals():
    #coletar as informações do JSON
    data = request.json
    user_id = current_user.id
    #capturar as informações contidas no JSON
    nome = data.get("nome")
    descricao = data.get("descricao")
    dieta = data.get("dieta")
    date_and_time = datetime.now(pytz.timezone("America/Sao_Paulo"))
    fdate_and_time = date_and_time.strftime("%Y-%m-%d %H:%M:%S")

    if nome and dieta:
        meals = Meals(nome=nome, descricao=descricao, role_diet=dieta, user_id=user_id, date_and_time=fdate_and_time)
        db.session.add(meals)
        db.session.commit()
        return jsonify({"message": "Refeição cadastrada com sucesso"})

    return jsonify({"message": "Dados inválidos"}), 400

@app.route('/meals/<int:meal_id>', methods=["PUT"])
@login_required
def update_meals(meal_id):

    data = request.json

    meal = db.session.get(Meals, meal_id)
    if not meal:
        return jsonify({"error": "Meal not found"}), 404

    user_id = current_user.id

    #pega a atualização dos campos no json
    id = meal_id
    nome = data.get("nome")
    descricao = data.get("descricao")
    date_and_time = data.get("date_and_time")
    role_diet = data.get("role_diet")

    print("coleta do json")

    if date_and_time:
        try:
            date_and_time = convert_to_mysql_datetime(date_and_time)
            print("Data reformatada:")

        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    meal = Meals.query.get(meal_id)

    if meal:
        db.session.execute(
            update(Meals).where(Meals.id == meal_id and user_id == current_user.id).values(
                nome=nome,
                descricao=descricao,
                date_and_time=date_and_time,
                role_diet=role_diet
            )
        )
        db.session.commit()
        return jsonify({"message": "Refeição atualizado com sucesso"})

    return jsonify({"message": "Registro não encontrado"}), 404

def convert_to_mysql_datetime(date_string):
    try:
        # Converte de "DD/MM/YYYY HH:MM" para "YYYY-MM-DD HH:MM:SS"
        parsed_date = datetime.strptime(date_string, "%d/%m/%Y %H:%M")
        return parsed_date.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise ValueError("Invalid date format. Expected DD/MM/YYYY HH:MM.")

@app.route('/meals/<int:meal_id>', methods=['DELETE'])
@login_required
def delete_meals(meal_id):

    meal = db.session.get(Meals, meal_id)

    if not meal:
        return jsonify({"error": "Refeição não encontrada"}), 404

    current_meal_user = current_user.id
    user_admin = current_user.role

    if user_admin == "admin" or meal.user_id == current_meal_user:
        db.session.delete(meal)
        db.session.commit()  # Confirma a exclusão no banco de dados
        return jsonify({"message": f"Registro de refeição #{meal_id}, foi deletado com sucesso."})

    return jsonify({"error": "Ação proibida, usuário não autorizado"}), 403


@app.route('/meals/<int:meal_id>', methods=['GET'])
@login_required
def search_meals(meal_id):

    meal = db.session.get(Meals, meal_id)

    if not meal:
        return jsonify({"error": "Refeição não encontrada"}), 404

    # Retorna os dados da refeição no formato JSON
    return jsonify({
        "id": meal.id,
        "date_and_time": meal.date_and_time.strftime("%d/%m/%Y %H:%M:%S"),
        "nome": meal.nome,
        "descricao": meal.descricao,
        "role_diet": meal.role_diet
    })



#TODO Deve ser possível listar todas as refeições de um usuário
@app.route('/meals/user/<int:user_id>', methods=['GET'])
@login_required
def search_user_meals(user_id):

    meals = Meals.query.filter_by(user_id=current_user.id).all()

    if not meals:
        return jsonify({"error": "Não há refeições registradas"}), 404

    # Retorna os dados da refeição no formato JSON
    return jsonify([{
        "id": meal.id,
        "date_and_time": meal.date_and_time.strftime("%d/%m/%Y %H:%M:%S"),
        "nome": meal.nome,
        "descricao": meal.descricao,
        "role_diet": meal.role_diet
    }for meal in meals])



if __name__ == '__main__':
    app.run(debug=True)



