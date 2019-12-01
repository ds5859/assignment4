#!/usr/bin/env python
from flask import Flask, render_template, request, url_for, flash, redirect, session
from forms import RegistrationForm, LoginForm, SpellForm, LoginHistoryForm, SpellHistoryForm
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import subprocess
import os
#from subprocess import PIPE
app = Flask(__name__)

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
#csrf.init_app(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
cwd = os.getcwd()
csrf_key = open('/run/secrets/csrf_key', 'r').read().strip()
app.secret_key = csrf_key
#app.config['SECRET_KEY'] = csrf_key
#app.config['SECRET_KEY'] = '4a6542b7886a0d46a36c1bf51f9a11ac720dde847d4b0a9b'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class userTable(UserMixin, db.Model):
    id = db.Column(db.Integer(), unique=True, nullable=False, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=False, nullable=False)
    twofa = db.Column(db.String(11), unique=False, nullable=True)
    useradmin = db.Column(db.Boolean(), unique=False, nullable=False, default=False)
    #userid = db.Column(db.Integer(), unique=True, nullable=False) #make primary key
    #boolean flag for admin/ or use admin uid / 
    def __repr__(self):
        return f"userTable('{self.id}','{self.username}','{self.password}','{self.twofa}','{self.useradmin}')"

class spellTable(UserMixin, db.Model):
    id= db.Column(db.Integer(), unique=True, nullable=False, primary_key=True)
    username = db.Column(db.String(100), unique=False, nullable=False)
    querytext = db.Column(db.String(1000000), unique=False, nullable=False)
    queryresults = db.Column(db.String(1000000), unique=False, nullable=False)

    def __repr__(self):
        return f"spellTable('{self.id}','{self.username}','{self.querytext}','{self.queryresults}')"

class logTable(UserMixin, db.Model):
    id = db.Column(db.Integer(), unique=True, nullable=False, primary_key=True)
    username = db.Column(db.String(100), unique=False, nullable=False)
    logintime = db.Column(db.DateTime)
    logouttime = db.Column(db.DateTime, default=None) #TODO: change default to N/A

    def __repr__(self):
        return f"logTable('{self.id}','{self.username}','{self.logintime}','{self.logouttime}')"


#db.drop_all() #for debugging purposes
db.create_all()



# admin account for gradescope
if userTable.query.filter_by(username='admin').first() == None:
    #OLD METHOD FOR ASSIGNMENT 3
    #hash_pword = bcrypt.generate_password_hash('Administrator@1').decode('utf-8')
    #admin = userTable(username='admin', password=hash_pword, twofa='12345678901', useradmin=True)
    #NEW METHOD FOR ASSIGNMENT 4: Retrieving info from Docker secrets
    docker_pword = open('/run/secrets/db_admin_pword', 'r').read().strip()
    docker_twofa = open('/run/secrets/db_admin_2fa', 'r').read().strip()
    hash_pword = bcrypt.generate_password_hash(docker_pword).decode('utf-8')
    admin = userTable(username='admin', password=hash_pword, twofa=docker_twofa, useradmin=True)
    db.session.add(admin)
    db.session.commit()

# admin account for debugging
if userTable.query.filter_by(username='admin0').first() == None:
    hash_pword = bcrypt.generate_password_hash('000000').decode('utf-8')
    admin0 = userTable(username='admin0', password=hash_pword, twofa=None, useradmin=True)
    db.session.add(admin0)
    db.session.commit()

@login_manager.user_loader
def load_user(id):
    return userTable.query.get(id)

@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized. Please Login.'

#@csrf.error_handler
###@app.errorhandler(CSRFProtect)
#def csrf_error(reason):
    #return render_template('csrf_error.html', reason=reason), 400

@app.route('/') #main page
@app.route('/index') #alt main page
def main():
    return render_template('home.html', pagename = 'Main Page')

@app.route('/logout')
#@login_required
def logout():
    print(current_user)
    curr = current_user.username
    print(curr)
    editlog = logTable.query.filter_by(username=curr, logouttime=None).first() #TODO: change default to N/A
    #print(editlog.logintime)
    #print(editlog.logouttime)
    #editlog = logTable(logouttime=datetime.utcnow()) 
    #editlog = logTable(logouttime=datetime.utcnow()) 

    editlog.logouttime = datetime.utcnow()
    #db.session.add(editlog)
    #db.__setattr__(editlog, logouttime=datetime.utcnow())
    db.session.add(editlog)
    db.session.commit()
    logout_user()
    print(current_user)

    print(editlog)
    flash('Logged Out Successfully', 'success')
    return redirect(url_for('main'))

@app.route('/register', methods=["POST", "GET"]) #registration page
def register():
    gradescope = ''
    if current_user.is_authenticated:
        flash('Already Logged In', 'info')
        return redirect(url_for('main'))
    form = RegistrationForm()
    if form.validate_on_submit():
        #local variables for form data
        user = form.uname.data
        pword = form.pword.data
        twofa = form.twofa.data
        hash_pword = bcrypt.generate_password_hash(form.pword.data).decode('utf-8')

        if userTable.query.filter_by(username=user).first() == None:
            if not form.twofa.data:
                newUser = userTable(username=user, password=hash_pword, twofa=None)
                db.session.add(newUser)
                db.session.commit()
                flash(f'Account created for {form.uname.data}. Please Login.', 'success')
                #userTable.query.all()
                gradescope = 'success'
                #return redirect(url_for('login'))
                return render_template('register.html', title = 'Success', pagename = 'Registration Page', gradescope = gradescope, form = form)
            else:
                newUser = userTable(username=user, password=hash_pword, twofa=twofa)
                db.session.add(newUser)
                db.session.commit()
                flash(f'Account created for {form.uname.data} with 2-Factor Authentication. Please Login.', 'success')
                #userTable.query.all()
                gradescope = 'success'
                #return redirect(url_for('login'))
                return render_template('register.html', title = 'Success', pagename = 'Registration Page', gradescope = gradescope, form = form)
        else:
            gradescope = 'failure'
            flash('Registration Error. Please select a different User Name', 'danger')
            return render_template('register.html', title = 'Failure', pagename = 'Registration Page', gradescope = gradescope, form = form)
    return render_template('register.html', title = 'Register', pagename = 'Registration Page', form = form)

@app.route('/login', methods=["POST", "GET"]) #login page
def login():
    #if current_user.is_authenticated:
        #flash('Already Logged In', 'info')
        #return redirect(url_for('main'))
    gradescope = ''
    form = LoginForm()
    if form.validate_on_submit():
        #local variables for form data
        user = form.uname.data
        pword = form.pword.data
        twofa = form.twofa.data
        dbuser = userTable.query.filter_by(username=user).first()
        if dbuser != None:
            #uname = form.uname.data
            if dbuser.twofa == None:
                if (bcrypt.check_password_hash(dbuser.password, pword)): 
                #if ((users[form.uname.data]['pword'] == form.pword.data) and (users[form.uname.data]['2fa'] == form.twofa.data)):
                #if form.uname.data == 'test123' and form.twofa.data == '123456789' and form.pword.data == 'test123':
                    #login_user(form.uname.data, remember=form.remember.data)
                    #User.curr_user = form.uname.data
                    #login_user(curr_user, remember=form.remember.data)
                    #user = User()
                    #user.id = uname
                    login_user(dbuser, remember=form.remember.data)
                    newlog = logTable(username=user, logintime=datetime.utcnow()) 
                    db.session.add(newlog)
                    db.session.commit()
                    flash('Logged in successfully', 'success')
                    #return 'Logged in as: ' + current_user.id
                    #print(login_user(dbuser))
                    #print(dbuser)
                    #print(dbuser.id)
                    print(current_user)
                    print(current_user.username)
                    print(session.values)
                    #return redirect(url_for('main'))
                    gradescope = 'Success'
                    return render_template('login.html', title = 'Login', pagename = 'Login Page', gradescope = gradescope, form = form)
                else:
                    flash('Unsuccessful Login', 'danger')
                    gradescope = 'Incorrect'
                    return render_template('login.html', title = 'Login', pagename = 'Login Page', gradescope = gradescope, form = form)
            #else if not form.twofa.data:
                #flash('Unsuccessful Login', 'danger')
            else:
                if (bcrypt.check_password_hash(dbuser.password, pword) and (dbuser.twofa == twofa)):
                #if ((users[form.uname.data]['pword'] == form.pword.data) and (users[form.uname.data]['2fa'] == form.twofa.data)):
                #if form.uname.data == 'test123' and form.twofa.data == '123456789' and form.pword.data == 'test123':
                    #login_user(form.uname.data, remember=form.remember.data)
                    #User.curr_user = form.uname.data
                    #login_user(curr_user, remember=form.remember.data)
                    #user = User()
                    #user.id = uname
                    login_user(dbuser, remember=form.remember.data)
                    newlog = logTable(username=user, logintime=datetime.utcnow()) 
                    db.session.add(newlog)
                    db.session.commit()
                    flash('Logged in successfully', 'success')
                    #return 'Logged in as: ' + current_user.id
                    #print(login_user(dbuser))
                    #print(dbuser)
                    #print(dbuser.id)
                    print(current_user)
                    print(current_user.username)
                    print(session.values)
                    gradescope = 'Success'
                    #return redirect(url_for('main'))
                    return render_template('login.html', title = 'Login', pagename = 'Login Page', gradescope = gradescope, form = form)
                else:
                    flash('Unsuccessful Login', 'danger')
                    gradescope = 'Incorrect'
                    return render_template('login.html', title = 'Login', pagename = 'Login Page', gradescope = gradescope, form = form)
        else:
            flash('Unsuccessful Login. No such User.', 'danger')
            gradescope = 'Incorrect'
            return render_template('login.html', title = 'Login', pagename = 'Login Page', gradescope = gradescope, form = form)
    return render_template('login.html', title = 'Login', pagename = 'Login Page', form = form)

    #return "Test Login Page"

@app.route('/spell_check', methods=["POST", "GET"]) #spellchecker
@login_required
def spell():
    form = SpellForm()
    #if login_user(user) == False:
        #flash('Please Log In', 'danger')
        #return redirect(url_for('login'))
    curr = current_user.username
    if form.validate_on_submit(): 
        flash('Submitted Successfully', 'success')
        inputtext = form.inputtext.data 
        with open('userinput.txt', 'w') as f:
            f.write(form.inputtext.data)
            f.close()

        #print(inputtext)
        #spellout = subprocess.Popen(['./a.out', 'userinput.txt', 'wordlist.txt'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) #use if using python3.6

        spellout = subprocess.run(['./a.out', 'userinput.txt', 'wordlist.txt'], check=True, stdout=subprocess.PIPE, universal_newlines=True) #BACKUP #use if using python3.6
        #spellout = subprocess.run(['./a.out', 'userinput.txt', 'wordlist.txt'], capture_output=True, text=True) # stderr=subprocess.DEVNULL

        with open('mispelled.txt', 'w') as g:
            g.write(spellout.stdout)
            g.close()
        with open('mispelled.txt', 'r') as g:
            mispelled = g.read().replace('\n', ', ').strip().strip(',')
            g.close()
        print(inputtext)
        print(mispelled)
        newlog = spellTable(username=curr, querytext=inputtext, queryresults=mispelled)
        db.session.add(newlog)
        db.session.commit()
        #spellout2 = spellout.stdout
        #print(spellout.stdout)
    
        return render_template('spell_check.html', title = 'Spell Checker', pagename = 'Spell Check Page', textout = inputtext, misspelled = mispelled, form = form)
    
    return render_template('spell_check.html', title = 'Spell Checker', pagename = 'Spell Check Page', form = form)

@app.route('/login_history', methods=["POST", "GET"]) #login history
@login_required
def login_history():
    form=LoginHistoryForm()
    curr = current_user
    
    #print(curr)
    if curr.useradmin == True:
        if form.validate_on_submit(): 
            inputtext = form.userid.data 
            dbuser = logTable.query.filter_by(username=inputtext).first()
            if dbuser != None:
                flash('Successful Query', 'success')
                #print(inputtext)
                history = logTable.query.filter_by(username=inputtext).all()
                print(history)


                return render_template('login_history.html', title = 'Login History', pagename = 'Login History -- ADMIN ACCESS ONLY', history = history, form = form)
            else:
                flash('No Log History for User', 'danger')
        #else:
            #flash('Unsuccessful Query', 'danger')
    else:
        return "Unauthorized"
    return render_template('login_history.html', title = 'Login History', pagename = 'Login History -- ADMIN ACCESS ONLY', form = form)

@app.route('/history', methods=["POST", "GET"]) #spell history
@login_required
def history():
    form=SpellHistoryForm()
    curr = current_user
    if curr.useradmin == True:
        if form.validate_on_submit():
            inputtext = form.userquery.data
            dbuser = spellTable.query.filter_by(username=inputtext).first()
            if dbuser != None:
                dbhistory = spellTable.query.filter_by(username=inputtext).all()
                #count = dbhistory.count('spellTable')
                count = len(dbhistory)
                print(count)
                print(dbhistory)
                #render template for results
                return render_template('history_result.html', title = 'Spell History', pagename = 'Spell History Results', user = inputtext, count=count, history = dbhistory)
            else: 
                flash('No Spell History for User', 'danger')
        return render_template('history.html', title='Spell History', pagename='Spell History', form=form)
    else:
        #dbuser = spellTable.query.filter_by(username=curr.username).first()
        #if dbuser != None:
        dbhistory = spellTable.query.filter_by(username=curr.username).all()
        #count = dbhistory.count('spellTable')
        count = len(dbhistory)
        print(count)
        print(dbhistory)
        #render template for results for user
        return render_template('history_result.html', title = 'Spell History', pagename = 'Spell History Results', user=curr.username, count=count, history = dbhistory)

@app.route('/history/query<log>')
@login_required
def querydetail(log):
    curr = current_user
    dbuser = spellTable.query.filter_by(id=log).first()
    if (curr.useradmin == True):
        dbquery = spellTable.query.filter_by(id=log).all()
        return render_template('query_details.html', title = 'Query Details', pagename = 'Query Details', query = dbquery)

    elif (curr.username == dbuser.username):
        dbquery = spellTable.query.filter_by(id=log).all()
        return render_template('query_details.html', title = 'Query Details', pagename = 'Query Details', query = dbquery)
    else:
        return "Unauthorized"

if __name__ == '__main__':
    app.run(debug=True)


