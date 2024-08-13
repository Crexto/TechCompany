from flask import *
import re
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
import sqlite3
import os

app = Flask(__name__)
app.secret_key = b'_53oi3urifpifpff;apl'
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

if not os.path.exists('userdata.db'):
	connection_obj = sqlite3.connect('userdata.db')
	cur = connection_obj.cursor()

	table = """ CREATE TABLE logininfo (
				userid INTEGER PRIMARY KEY,
				email VARCHAR(255) NOT NULL,
				username VARCHAR(255) NOT NULL,
				password VARCHAR(255) NOT NULL,
				admin BOOLEAN NOT NULL
			); """

	cur.execute(table)
	cur.execute(f"INSERT INTO logininfo VALUES (NULL ,'admin', 'admin', '{bcrypt.generate_password_hash('admin').decode('utf-8')}',1)")
	connection_obj.commit()
	connection_obj.close()
	print("Database initiated")

if not os.path.exists('store.db'):
	connection_obj = sqlite3.connect('store.db')
	cur = connection_obj.cursor()

	table = """ CREATE TABLE tags(
				name VARCHAR(255) NOT NULL
			); """

	cur.execute(table)

	table = """ CREATE TABLE products (
				name VARCHAR(255) PRIMARY KEY,
				price CHARACTER(20) NOT NULL,	
				stock BOOLEAN NOT NULL,	
				picture BLOB NOT NULL,	
				tag VARCHAR(255) NOT NULL
			); """

	cur.execute(table)
	cur.execute(f"INSERT INTO tags VALUES ('Graphic Cards')")
	ss = open('pic1.jpg','rb').read()
	cur.execute(f"INSERT INTO products VALUES (?,?,?,?,?)",('RTX 4090', "1,000,000",1,ss,'Graphic Cards'))
	connection_obj.commit()
	connection_obj.close()
	print("Database initiated")

def CaseConvert(case):
	return " ".join([x[0].capitalize()+x[1::].lower() for x in case.split()])


@app.route("/")
def home():
	return render_template("home.html")

@app.errorhandler(404) 
def not_found(e): 
  return render_template("n404.html") 

@app.route('/register', methods=['GET', 'POST'])
def register():
	message = ''
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
		userName = request.form['username']
		password = request.form['password']
		email = request.form['email']

		connection_obj = sqlite3.connect('userdata.db')
		cur = connection_obj.cursor()

		cur.execute(f"SELECT * FROM logininfo WHERE email = '{email}'")
		account = cur.fetchone()

		if account:
			message = 'Account already exists!'
		elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
			message = 'Invalid email address!'
		elif not userName or not password or not email:
			message = 'Please fill out the form!'
		else:
			password = bcrypt.generate_password_hash(password).decode('utf-8')
			cur.execute(f"INSERT INTO logininfo VALUES (NULL ,'{email}', '{userName}', '{password}',0)")
			message = 'You have successfully registered !'
			connection_obj.commit()
			connection_obj.close()
			return redirect(url_for('home'))
		
		connection_obj.close()
	elif request.method == 'POST':
		message = 'Please fill out the form!'
	return render_template('register.html', message=message)


@app.route("/login", methods=["GET", "POST"])
def login():
	message = ''
	if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
		email = request.form['email']
		password = request.form['password']

		connection_obj = sqlite3.connect('userdata.db')
		cur = connection_obj.cursor()

		cur.execute(f"SELECT * FROM logininfo WHERE email = '{email}'")
		user = cur.fetchone()
		connection_obj.close()

		if user:
			if bcrypt.check_password_hash(user[3], password):
				session['loggedin'] = True
				session['userid'] = user[0]
				session['email'] = user[1]
				session['username'] = user[2]
				session['admin'] = (True if user[4] == 1 else False)
				
				message = 'Logged in successfully!'
				return redirect(url_for('home'))
			else:
				message = 'Please enter correct email / password!'
		else:
			message = 'Please enter correct email / password!'

	return render_template('login.html',message=message)


@app.route('/products')
def store():
	
	connection_obj = sqlite3.connect('store.db')
	cur = connection_obj.cursor()
	cur.execute(f"SELECT * FROM tags")
	tags = [x[0] for x in cur.fetchall()]
	tag = request.args.get('tag')
	
	if request.args.get('tag'):
		tag = CaseConvert(request.args.get('tag'))

		if tag in tags:
			cur.execute(f"SELECT * FROM products WHERE tag = '{tag}'")
			products = cur.fetchall()
			connection_obj.close()

			return render_template('store.html',products=products,prodlen=len(products),tags=tags,taglen=len(tags))
		else:
			connection_obj.close()
			return render_template('store.html',products=None,prodlen=0,tags=tags,taglen=len(tags))
	else:
		cur.execute(f"SELECT * FROM products")
		products = cur.fetchall()
		connection_obj.close()

		return render_template('store.html',products=products,prodlen=len(products),tags=tags,taglen=len(tags))
	


@app.route('/image/<item>')
def image(item):
	connection_obj = sqlite3.connect('store.db')
	cur = connection_obj.cursor()
	cur.execute(f"SELECT * FROM products WHERE name = '{item}'")
	r = Response(response=cur.fetchone()[3], status=200, mimetype="image/png")
	connection_obj.close()
	r.headers["Content-Type"] = "image/png;"
	return r

@app.route('/profile')
def profile():
	return render_template("profile.html")
	
	

@app.route('/admin',methods=["POST","GET"])
def admin():
	if not session.get('admin'):
		return redirect(url_for('profile'))
		
	connection_objs = sqlite3.connect('store.db')
	curs = connection_objs.cursor()

	connection_obju = sqlite3.connect('userdata.db')
	curu = connection_obju.cursor()

	if request.method == 'POST':

		method = request.args.get('method')
		print(request.form)
		match method:
			case "storeadd":
				curs.execute(f"INSERT INTO products VALUES (?,?,?,?,?)",(request.form['ItemName'], f'{int(request.form['ItemPrice']):,}',request.form['stock'],request.files['Photo'].stream.read(),request.form['tag']))

			case "storeremove":
				curs.execute(f"DELETE FROM products WHERE name = '{request.form["name"]}'")

			case "tagadd":
				curs.execute(f"INSERT INTO tags VALUES ('{CaseConvert(request.form["TagName"])}')")

			case "tagremove":
				curs.execute(f"DELETE FROM tags WHERE name = '{request.form["name"]}'")
				
			case "adminadd":
				curu.execute(f"UPDATE logininfo SET admin=1 WHERE username='{request.form["name"]}'")
			
			case "adminremove":
				if session['username'] == request.form["name"]:
					session['admin'] = 0
				
				curu.execute(f"UPDATE logininfo SET admin=0 WHERE username='{request.form["name"]}'")
		
		connection_obju.commit()
		connection_objs.commit()
		# connection_objs.close()
		# connection_obju.close()

		return redirect(url_for("admin"))
	
	else:

		curs.execute(f"SELECT * FROM tags")
		tags = [x[0] for x in curs.fetchall()]
		curs.execute(f"SELECT * FROM products")
		products = curs.fetchall()
		# connection_objs.close()

		curu.execute(f"SELECT username FROM logininfo WHERE admin=1")
		admins = curu.fetchall()
		curu.execute(f"SELECT username FROM logininfo WHERE admin=0")
		users = curu.fetchall()
		# connection_obju.close()

		return render_template("admin.html",tags=tags,taglen=len(tags),products=products,prodlen=len(products),admins=admins,adminlen=len(admins),users=users,userlen=len(users))


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('username', None)
    session.pop('userid', None)
    session.pop('email', None)
    session.pop('admin', None)
    return redirect(url_for('home'))


if __name__ == "__main__":
	app.run(debug=True)

