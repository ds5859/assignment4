from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional

class RegistrationForm(FlaskForm):
    uname = StringField('Username', id="uname", validators=[DataRequired(), Length(min=5, max=20)])
    twofa = StringField('Phone/2FA (Optional)', id="2fa", validators=[Optional(strip_whitespace=True), Length(min=10, max=11)])
    #2fa = StringField('Phone/2FA (Optional)', validators=[Optional(strip_whitespace=True), Length(min=2, max=11)])
    pword = PasswordField('Password', id="pword", validators=[DataRequired(), Length(min=6, max=20)])
    #confirm_pword = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=2, max=20), EqualTo('pword')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    uname = StringField('Username', id="uname", validators=[DataRequired(), Length(min=5, max=20)])
    twofa = StringField('Phone/2FA (Optional)', id="2fa", validators=[Optional(strip_whitespace=True), Length(min=10, max=11)])
    #2fa = StringField('Phone/2FA (Optional)', validators=[Optional(strip_whitespace=True), Length(min=2, max=11)])
    pword = PasswordField('Password', id="pword", validators=[DataRequired(), Length(min=6, max=20)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class SpellForm(FlaskForm):
    inputtext = TextAreaField('Type or Paste Text Below', id="inputtext", validators=[DataRequired()])
    submit = SubmitField('Submit')
    textout = TextAreaField('Original Input')
    misspelled = TextAreaField('Misspelled Words', id="misspelled", validators=[])

class LoginHistoryForm(FlaskForm):
    userid = StringField('Username', id="userid", validators=[DataRequired()])
    history = TextAreaField('History')
    submit = SubmitField('Search')

class SpellHistoryForm(FlaskForm):
    userquery = StringField('Username', id="userquery", validators=[DataRequired()])
    history = TextAreaField('History')

    submit = SubmitField('Search')

    
