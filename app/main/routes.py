from flask import render_template, flash, redirect, url_for, current_app, request
from app import db
from app.models import Trade, User
from app.main import bp
from flask_login import current_user, login_required, login_user, logout_user


@bp.route('/', methods=['GET', 'POST'])
@bp.route('/index', methods=['GET', 'POST'])
# @login_required
def index():
    return render_template('index.html', title='Home')


@bp.route('/journal')
# @login_required
def journal():
    user = User.query.filter_by(username="gpaynter").first()
    trades = Trade.query.filter_by(user=user).all()
    return render_template('journal.html', title="Journal", positions=trades)
