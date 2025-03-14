from flask import Flask, request, jsonify, render_template, abort, make_response, url_for, session, redirect
from flask_cors import CORS
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import jwt
import json
import requests
import time
import random

app = Flask(__name__)
app.secret_key = str(random.randint(536804,78213213765))
CORS(app)
ip = "43.204.152.119"

with open('private_key.pem', 'rb') as key_file:
	private_key = key_file.read()

@app.route('/.well-known/jwk.json')
def json_file():
	with open('key.json') as f:
		data = json.load(f)
	return jsonify(data)

@app.route('/')
def home():
	return render_template('index.html')

@app.route('/login', methods=['POST'])
def auth():
	username = request.form['username']
	password = request.form['password']
	if username == "tuhin1729" and password == "@_pwd1993_1729":
		encoded = jwt.encode({"username": f"{username}"}, private_key, algorithm="RS256", headers={"kid": "1729", "jku": f"http://{ip}:8080/.well-known/jwk.json"})
	else:
		return "Invalid Username/Password!"

	resp = make_response(redirect(url_for('validate')))
	resp.set_cookie('auth', encoded, max_age=60*60*24)
	return resp

@app.route('/dashboard')
def validate():
	token = request.cookies.get('auth')
	if not token:
		resp = make_response(redirect(url_for('home')))
		return resp

	try:
		kid = jwt.get_unverified_header(token)['kid']
		jku = jwt.get_unverified_header(token)['jku']
		if not jku.startswith(f"http://{ip}"):
			return f"Only {ip} is allowed in JKU."
		r = requests.get(jku)
		public_keys = {}
		jwks = r.json()
		for jwk in jwks['mykeys']:
			kid = jwk['kid']
			public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
		key = public_keys[kid]
		payload = jwt.decode(token, key=key, algorithms=['RS256'])
		# print(key)
		if payload["username"] == "admin":
			# return open('flag.txt','r').read()
			return render_template('dashboard.html')
		else:
			return f"Welcome, {payload['username']}"
	except Exception as e:
		print(e)
		return "Something went wrong"

@app.route('/contactus', methods=['GET','POST'])
def contact():
	token = request.cookies.get('auth')
	if not token:
		resp = make_response(redirect(url_for('home')))
		return resp

	try:
		kid = jwt.get_unverified_header(token)['kid']
		jku = jwt.get_unverified_header(token)['jku']
		if not jku.startswith(f"http://{ip}"):
			return f"Only {ip} is allowed in JKU."
		r = requests.get(jku)
		public_keys = {}
		jwks = r.json()
		for jwk in jwks['mykeys']:
			kid = jwk['kid']
			public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
		key = public_keys[kid]
		payload = jwt.decode(token, key=key, algorithms=['RS256'])
		# print(key)
		if payload["username"] != "admin":
			return abort(403)
	except Exception as e:
		print(e)
		return "Something went wrong"

	if request.method == 'POST':
		message = request.form.get('message')
		url = f"http://{ip}:8080/admin?message={message}"
		chrome_options = Options()
		chrome_options.add_argument('--headless')
		chrome_options.add_argument('--no-sandbox')
		browser = webdriver.Chrome(options=chrome_options)
		browser.get(url)
		time.sleep(4)
		browser.quit()
	return render_template('contact.html')

@app.route('/admin', methods = ['GET'])
def admin():
	#To be Added Soon

@app.route('/proxy', methods=['GET'])
def proxy():
    #To be Added Soon

@app.route('/flag')
def flag():
    if request.remote_addr == '127.0.0.1' or request.remote_addr == '::1' or request.remote_addr == ip:
        with open('flag.txt','r') as file:
            a = file.read()
        return a
    else:
        return abort(403)

if __name__ == '__main__':
	app.run('0.0.0.0', 8080)
