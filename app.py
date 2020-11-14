from flask import Flask
from flask import Flask, flash, redirect, render_template, request, session, abort
import os
import re

app = Flask(__name__, template_folder='templates') 
from flask.ext.session import Session
from flask.ext.profile import Profiler

@app.route('/')    #todo return and open html page
def home():
   
    if not session.get('logged_in'):
        return render_template('login.html.html')
    else:
        return "Hello Boss!"
    
    
    
    

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
def check(email):  
    if(re.search(regex,email)):  
        print("Valid Email")         
    else:  
         return home
def password_check(passwd): 
      
    SpecialSym =['$', '@', '#', '%'] 
    val = True
      
    if len(passwd) < 6: 
        print('length should be at least 6') 
        val = False
          
    if len(passwd) > 20: 
        print('length should be not be greater than 8') 
        val = False
          
    if not any(char.isdigit() for char in passwd): 
        print('Password should have at least one numeral') 
        val = False
          
    if not any(char.isupper() for char in passwd): 
        print('Password should have at least one uppercase letter') 
        val = False
          
    if not any(char.islower() for char in passwd): 
        print('Password should have at least one lowercase letter') 
        val = False
          
    if not any(char in SpecialSym for char in passwd): 
        print('Password should have at least one of the symbols $@#') 
        val = False
    if val: 
        return val 
    
    
    
    
    
    
    
      

@app.route('/login', methods=['POST'])
def do_admin_login():      #todo this api use for loging page with validtion
  #  global check_pwd
    pattern = re.compile(r'([a-zA-Z])\D*([a-zA-Z])$')
    firstname= request.form['FirstName']
    LastName =  request.form['LastName']
    Email = request.form['Email']
    MobileNumber = request.form['MobileNumber']
    rule = re.compile(r'(^[+0-9]{1,3})*([0-9]{10,11}$)')
    password = request.form['password']
    confirmpassword =  request.form['confirmpassword']
    if firstname == pattern:
        session['logged_in'] = True      
    if LastName == pattern:
        session['logged_in'] = True
   
    if check(Email):
         session['logged_in'] = True
    
    if rule.search(MobileNumber):  
         session['logged_in'] = True
         
    if (password_check(password)): 
         session['logged_in'] = True
         
    if password == confirmpassword:
        session['logged_in'] = True
    else:
        flash('Please Enter Valid Input')
    return home()



@app.route('/register', methods=['GET', 'POST'])
def register():                                    #todo maintain session here and use for track session id 
    from registration.forms import RegistrationForm
    form = RegisterForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                new_user = User(form.email.data, form.password.data)
                new_user.authenticated = True
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                send_confirmation_email(new_user.email)
                flash('Thanks for registering!  Please check your email to confirm your email address.', 'success')
                return redirect(url_for('recipes.index'))
            except IntegrityError:
                db.session.rollback()
                flash('ERROR! Email ({}) already exists.'.format(form.email.data), 'error')
    return render_template('register.html', form=form)









@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    from app.forms import EditProfileForm
    form = EditProfileForm()
    current_user= request.form['FirstName']
    
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
       # db.session.commit()
        flash('Your changes have been saved.')
        return redirect(('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html')



@app.route('/register', methods=['GET', 'POST'])
def user_profile():
    return render_template('user_profile.html')

if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(host='localhost',debug=False)