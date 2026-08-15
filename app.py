from flask import Flask, request, jsonify
from flask_cors import CORS 
import mysql.connector
import bcrypt
app = Flask(__name__)
CORS(app)

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',#enter password here  
    'database': ''#enter the name of database               
}

@app.route('/api/login', methods=['POST'])
def handle_login_or_register():
    data = request.json
    submitted_email = data.get('email')
    submitted_password = data.get('password')
    submitted_username = data.get('username', 'Unknown')
    
    user_ip = request.remote_addr
    user_browser = request.headers.get('User-Agent', 'Unknown Browser')
    
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    
    # STEP 1: Search your master directory 'user' table for this email
    cursor.execute("SELECT * FROM user WHERE email = %s", (submitted_email,))
    db_user = cursor.fetchone()
     if(db_user):
        if bcrypt.checkpw(submitted_password.encode('utf-8'), db_user["password"].encode('utf-8')):

            login_status="success"
            ui_message="Login "
            http_status_code=200
        else:
              login_status="failed to login"
              ui_message="Wrong password "
              http_status_code=401 
             
    else:

        email=submitted_email
        name=submitted_username
        password=submitted_password

        bytes=submitted_password.encode('utf-8')
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(bytes, salt)
        hashed_pass = hash.decode('utf-8')
    
        sql_query="INSERT INTO user (email, password, username)VALUES(%s,%s,%s)"
        data_insert=(email, hashed_pass ,name)
        cursor.execute(sql_query, data_insert)
        print("Account Created Successfully")
        
        login_status = "ACCOUNT_AUTO_CREATED"
        ui_message = "Account created and logged in automatically!"
        http_status_code = 201

    # STEP 2: PERMANENTLY WRITE LOG DETAILS
    # No matter what happened above, we write down the full snapshot to 'login_logs'
    log_query = """
        INSERT INTO login_logs (username, email, password, status, ip_address, user_agent)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    cursor.execute(log_query, (submitted_username, submitted_email, submitted_password, login_status, user_ip, user_browser))

    # Save all database changes cleanly
    conn.commit()
    cursor.close()
    conn.close()
    
    # STEP 3: Return the outcome package back across Bridge 1 to your browser
    return jsonify({"success": login_status in ["SUCCESS", "ACCOUNT_AUTO_CREATED"], "message": ui_message}), http_status_code

if __name__ == '__main__':
    app.run(debug=True, port=5000)
