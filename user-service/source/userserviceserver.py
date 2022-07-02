from waitress import serve
from userservice import app
import os

HOST = os.environ.get('HOST', 'localhost')
PORT = os.environ.get('PORT', 8080)

print("Serving FootballSim user service on http://" + HOST + ":" + PORT)
serve(app, host=HOST, port=PORT)