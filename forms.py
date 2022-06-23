from ast import Pass
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Email, Length, EqualTo
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField


class UserForm(FlaskForm):
    username = StringField("Enter your name", validators=[
                           DataRequired(), Length(min=2, max=10)])
    email_id = StringField("Email address", validators=[
                           DataRequired(), Email()])
    password_hash = PasswordField("Password", validators=[
                                  DataRequired(), EqualTo('password_hash2')])
    password_hash2 = PasswordField(
        "Confirm Password", validators=[DataRequired()])
    favorite_anime = StringField("Favorite Anime")
    submit = SubmitField("Submit")


class PasswordTestForm(FlaskForm):
    email_id = StringField("Email address", validators=[
                           DataRequired(), Email()])
    password_hash = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    # content = StringField("Content", widget=TextArea())
    content = CKEditorField('Content', validators=[DataRequired()])
    author = StringField("Author")
    slug = StringField("Slug", validators=[DataRequired()])
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password_hash = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class SearchForm(FlaskForm):
    searched = StringField("Username", validators=[DataRequired()])
    submit = SubmitField("Submit")
