from flask import Flask,render_template,url_for,request,jsonify,redirect,flash

from flask_wtf import FlaskForm
from wtforms import StringField,EmailField,SubmitField,PasswordField
from wtforms.validators import DataRequired,Email
import flask_login
from dotenv import load_dotenv
import csv , json, os, hashlib, binascii

from bleach import clean

from Database import get_db_connection,Database

from supabase import create_client


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('CSRF_SECRET_KEY')

login_manager = flask_login.LoginManager()
login_manager.init_app(app)

db = None

#database thingssssss
#should allow for development using a dev database
if app.debug:
    DATABASE_URL = os.environ.get('DEV_DATABASE_URL')
    #database object instance 
    db = Database(DATABASE_URL)
else:
    #use supabase here ?
    DATABASE_URL = os.environ.get('DATABASE_URL')



class SignupForm(FlaskForm):
    username = StringField('Username: ',validators=[DataRequired()])
    email = EmailField('Email: ',validators=[DataRequired()])
    password = PasswordField('Password: ',validators=[DataRequired()])
    submit = SubmitField("Submit")

class LoginForm(FlaskForm):
    username = StringField('Username: ',validators=[DataRequired()])
    email = EmailField('Email: ',validators=[DataRequired()])
    password = PasswordField('Password: ',validators=[DataRequired()])
    submit = SubmitField("Submit")

supabase = create_client(os.environ.get('SUPA_PROJECT_URL'),os.environ.get('SUPA_API_KEY'))

##USER MANAGEMENT
class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(id):
    sql = "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = %s)"
    values = (id,)
    result,rows = db.get(sql,values)
    user_exists = rows
    
    if user_exists[0]['exists'] == True:

        sql = "SELECT * FROM users WHERE user_id = %s"
        values = (id,)
        result,rows = db.get(sql,values)
        info = rows[0] 

        user = User()
        user.id = info['user_id']
        user.username = info['username']
        user.email = info['email']
        return user
    else:
        return None

@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    # con = get_db()
    # cur = con.cursor()

    sql = "SELECT EXISTS(SELECT 1 FROM users WHERE email = %s)"
    values = (email,)
    result,rows = db.get(sql,values)
    user_exists = rows

    if user_exists[0]['exists'] == True:

        sql = "SELECT * FROM users WHERE email = %s"
        values = (email,)
        result,rows = db.get(sql,values)
        info = rows[0] 

        user = User()
        user.id = info['user_id']
        user.username = info['username']
        user.email = info['email']
        return user
    else:
        return None


#                               ROUTES 
@app.route("/")
def index():
    return render_template("index.html")

##signup route 

@app.route('/signup',methods=['GET','POST'])
def signup():
    #this is where a class would be useful lol 
    username = None
    email = None
    password = None

    form = SignupForm()

    if form.validate_on_submit():
        username = form.username.data
        form.username.data = ''

        email = form.email.data
        form.email.data = ''

        password = form.password.data # might need to hash it here
        form.password.data = ''

        #password salt
        salt = os.urandom(32)

        hashed = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt,1000) #iterations was 100,000 but i chose 1000

        salt_hex = binascii.hexlify(salt).decode('utf-8')

        sql = "INSERT INTO users (username,email,hash,salt) VALUES (%s,%s,%s,%s)"
        # values = (username,email,hashed,salt,)
        values = (username,email,binascii.hexlify(hashed).decode('utf-8'),salt_hex)

        result, message = db.insert(sql,values)

        if result:
            return redirect('/login')
        else:
            return redirect(url_for('signup',errors=f'{message}'))

    if request.method == 'GET':
        #look for error messag in the url 
        errors = request.args.get('errors')
        return render_template("signup.html",username=username,email=email,password=password,form=form,errors=errors)

##LOGIN

@app.route('/login',methods=['GET','POST'])
def login():
    username = None
    email = None
    password = None

    form = LoginForm()

    if form.validate_on_submit(): ##POST
        username = form.username.data
        form.username.data = ''

        email = form.email.data
        form.email.data = ''

        password = form.password.data # might need to hash it here
        form.password.data = ''

        app.logger.info(f"USER LOGIN email:{email}")
        #check for the presence of the user in the db 
        result,userInfo = db.get("SELECT user_id,username,email,hash,salt FROM users WHERE email = %s",values=(email,))
        app.logger.info(f"USER LOGIN RESULT:{result} , message: {userInfo}")
        if userInfo:
            app.logger.info(f"DATA IN USER INFO")
        else:
            #redirect  with message of no user 
            app.logger.info(f"NO DATA IN USER INFO")
            flash("No user profile")
            return redirect(url_for('login'))

        #hash the password
        salt = binascii.unhexlify(userInfo[0]['salt'])
        hashed = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt,1000)
        hashed_hex = binascii.hexlify(hashed)

        app.logger.info(f" DB hash = {userInfo[0]['hash']}  :: input hex {hashed_hex.decode('utf-8')}")

        if hashed_hex.decode('utf-8') == userInfo[0]['hash']:
            app.logger.info("USER LOGGED IN")
            user = User()
            user.id = userInfo[0]['user_id']
            user.username = userInfo[0]['username']
            user.email = userInfo[0]['email']

            flask_login.login_user(user)
            return redirect('/profile')

        else:
            app.logger.info("USER NOT LOGGED IN")
            return render_template('login.html', form=form, errors="something went wrong. try again")
        
    #ther is no else for the above valid form check so may need that in future 
    
    if request.method == 'GET':
        #look for error messag in the url 
        errors = request.args.get('errors')
        return render_template("login.html",form=form,errors=errors)


#add login required decorator 
@app.route("/profile",methods=['GET','POST'])
@flask_login.login_required
def profile():
    #get the logged in user 
    currentUser = None

    if flask_login.current_user.is_authenticated:
        currentUser = flask_login.current_user

    return render_template("profile.html",user=currentUser)

@app.route("/createEntry",methods=['GET','POST'])
@flask_login.login_required
def createEntry():

    if request.method == "POST":

        app.logger.info(f"REQUEST FORM DATA {request.form}")
        entryName =  clean(request.form.get('entryName'))
        #validate and ecape the name 

        macros = {
            "calories":None,
            "protein":None,
            "fats":None,
            "carbs":None,
            "fibre":None
        }
                #macro info
        calories = request.form.get('calories')
        protein = request.form.get('protein')
        fats = request.form.get('fats')
        carbs = request.form.get('carbs')
        fibre = request.form.get('fibre')

        #sanitize and check for negative values 
        
        macros["calories"] = calories
        macros["protein"] = protein
        macros['fats'] = fats
        macros['carbs'] = carbs
        macros['fibre'] = fibre

        sql = """INSERT INTO public.entry(
	        entry_data, entry_name, user_id)
	        VALUES (%s,%s,%s);"""
        values = (json.dumps(macros),entryName,flask_login.current_user.id)

        result, message = db.insert(sql,values)

        if result:
            flash("Entry saved")
        else:
            flash(f"Entry not saved -- {message}")

        return redirect(url_for("createEntry"))

    return render_template("createEntry.html")


@app.route("/logout")
def logout():
    flask_login.logout_user()
    return redirect(url_for('index'))

@login_manager.unauthorized_handler
def unauthorized_handler():
    #return "Unauthorized", 401
    return redirect(url_for('index'))









##for render to run 
if __name__ == "__main__":
    app.run()
    