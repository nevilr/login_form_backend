import psycopg2
import jwt
import bcrypt
from flask import Flask, request, jsonify
import re
import os


os.environ["SECRET_KEY"] = 'gerbvi4b43ubt4i3b4vh34398698bfdvb'
os.environ["host"] = "localhost"
os.environ["database"] = "RESTFUL_API"
os.environ["user"] = "postgres"
os.environ["password"] = "adminraithatha123456789"

app = Flask(__name__)

try:
    conn = psycopg2.connect(host=os.environ["host"], database=os.environ["database"], user=os.environ["user"],
                            password=os.environ["password"])
except Exception as error:
    print("Connection to database failed!")
    print("Error: ", error)


@app.route("/signup", methods=["POST"])
def create_user():
    try:
        data = request.json
        email_pattern = r"^[A-Za-z0-9._%+-]+\.[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}$"
        password_patten = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
        # password_patten = "^(?=.*?[a-z])(?=.*?[0-9]).{8,}$"
        name_pattern = "^(?=.*?[A-Za-z]).{1,30}$"
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')
        if re.fullmatch(email_pattern, email) and re.fullmatch(password_patten, password) and \
                re.fullmatch(name_pattern, first_name) and re.fullmatch(name_pattern, last_name)\
                and not first_name.lower() in password.lower() and not last_name.lower() in password.lower():
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            with conn.cursor() as cur:
                cur.execute(f"""SELECT * FROM user_login WHERE email='{email}'""")
                existing_user = cur.fetchone()
                if existing_user:
                    return {"error": "Email already exists."}
                else:
                    cur.execute(
                        f"""INSERT INTO user_login (email, password) VALUES ('{email}', '{hashed_password.decode()}')
                         RETURNING user_id""")
                    user_id = cur.fetchone()[0]
                    cur.execute(
                        f"""INSERT INTO user_data (user_id, first_name, last_name) 
                        VALUES ('{user_id}', '{first_name}', '{last_name}')""")
                    conn.commit()
                    conn.commit()
                    return jsonify({"message": "User created successfully"})
        else:
            return {"error": """Please enter valid data.
            - First name and Last name should not be in the password.
            - Password should be at least 8 characters long.
            - Password should contain at least 1 uppercase alphabet, 1 lowercase alphabet, 1 number and 1 symbol.
            -Entered email needs to be valid ex. abc.example@gmail.com.
            """}
    except Exception as e:
        print("Error: ", e)
        return jsonify({"error": "An error occurred"})


@app.route("/login", methods=["POST"])
def login_user():
    try:
        data = request.json
        email_pattern = r"^[A-Za-z0-9._%+-]+\.[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}$"
        password_patten = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
        # password_patten = "^(?=.*?[a-z])(?=.*?[0-9]).{8,}$"
        email = data.get('email')
        password = data.get('password')
        if re.fullmatch(email_pattern, email) and re.fullmatch(password_patten, password):
            with conn.cursor() as cur:
                cur.execute(f"""SELECT * FROM user_login WHERE email='{email}'""")
                user = cur.fetchone()
                if user:
                    hashed_password = user[2]
                    if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                        payload = {"email": email}
                        token = jwt.encode(payload, os.environ["SECRET_KEY"], algorithm="HS256")
                        return jsonify({"token": token})
                    else:
                        print("Passwords do not match.")
                else:
                    return jsonify({"error": "Invalid login credentials"})
        else:
            return {"error": "Please enter valid login credentials."}
    except Exception as e:
        print("Error: ", e)
        return jsonify({"error": "An error occurred"})


if __name__ == '__main__':
    app.run(debug=True)
