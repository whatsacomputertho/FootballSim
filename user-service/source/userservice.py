from flask import Flask
from flask_mysqldb import MySQL
from dotenv import load_dotenv
import os

#Load environment variables
load_dotenv('./source/.env')

#Initialize flask application
app = Flask(__name__)
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQL_PORT', 3306))
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'None')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'None')
app.config['MYSQL_CHARSET'] = os.environ.get('MYSQL_CHARSET', 'utf8')

#Initialize the mysql extension
mysql = MySQL(app)

@app.route('/api/v0/debug/')
def debug():
    try:
        cur = mysql.connection.cursor()
        cur.execute('''SELECT * FROM user''')
        rv = cur.fetchall()
        return {"users": str(rv)}
    except Exception as e:
        return {"error":str(e)}

@app.route('/api/v0/login/', methods=['POST'])
def login():
    #TODO: Receive email and password from request body
    #TODO: Check database for user
    #TODO: Create session for user
    #TODO: Return session ID
    return {"hello":"world"}

@app.route('/api/v0/register/')
def register():
    return {"hello":"world"}

@app.route('/api/v0/deactivate/')
def deactivate():
    return {"hello":"world"}