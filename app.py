# NOTE:
# Plain-text passwords are used only for learning purposes.
# Password hashing will be added in a future update.
from flask import Flask, request, jsonify
from flask_cors import CORS 
import mysql.connector

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
    
    login_status = "FAILED"
    ui_message = "Invalid password."
    http_status_code = 401
    #below code is write externally after making webpage
    if db_user:
        # PATH A: The user already exists in your vault! Check their password
        if db_user['password'] == submitted_password:
            login_status = "SUCCESS"
            ui_message = "Logged in successfully!"
            http_status_code = 200
        else:
            login_status = "WRONG PASSWORD"
            ui_message = "Incorrect password for this account."
            http_status_code = 401
    else:
        # PATH B: 🚀 AUTO-REGISTER! This email does not exist yet.
        # Let's save their brand-new credentials into the 'user' table immediately.
        register_query = """
            INSERT INTO user (username, email, password) 
            VALUES (%s, %s, %s)
        """
        cursor.execute(register_query, (submitted_username, submitted_email, submitted_password))
        
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
