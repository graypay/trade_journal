from app import db, login
import uuid
import requests
import re
from datetime import datetime, date
from sqlalchemy.orm import backref
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, current_user

NAMESPACE_GPFIX = uuid.uuid5(uuid.NAMESPACE_DNS, "gpfix.net")
TIME_FORMAT = "%m/%d/%y %I:%M:%S %p"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    created_at = db.Column(db.DateTime, index=True, nullable=False)
    updated_at = db.Column(db.DateTime, index=True, nullable=False)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    trades = db.relationship('Trade', backref=backref("user", lazy="joined"))
    accounts = db.relationship('TradeAccount', backref=backref("user", lazy="joined"))
    strategies = db.relationship('TradeStrategy', backref=backref("user", lazy="joined"))

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.set_password(password)
        now = datetime.utcnow()
        self.created_at = now
        self.updated_at = now
        self.set_uuid()

    def __repr__(self):
        return '<User {} - {} ({})>'.format(self.username, self.email, self.uuid)

    def set_uuid(self):
        self.uuid = str(uuid.uuid5(NAMESPACE_GPFIX, self.email))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        data = {
            "uuid": self.uuid,
            "username": self.username,
            "email": self.email,
            "_meta": {
                "self": "URL FOR THE USER"
            }
        }
        return data

    def create_from_dict(self, data):
        for field in ['username', 'email']:
            setattr(self, field, data[field])

        timestamp = datetime.utcnow()

        for field in ['created_at', 'updated_at']:
            setattr(self, field, timestamp)

        self.set_uuid()

        if 'password' in data:
            self.set_password(data['password'])


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    created_at = db.Column(db.DateTime, index=True, nullable=False)
    updated_at = db.Column(db.DateTime, index=True, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, nullable=False)

    status_id = db.Column(db.ForeignKey('trade_status.id'))
    user_id = db.Column(db.ForeignKey('user.id'))
    position_id = db.Column(db.ForeignKey('trade_position.id'))
    strategy_id = db.Column(db.ForeignKey('trade_strategy.id'))
    account_id = db.Column(db.ForeignKey('trade_account.id'))
    security_id = db.Column(db.ForeignKey('security.id'))
    trade_id = db.Column(db.ForeignKey('trade.id'))

    notes = db.relationship('TradeNote', backref=backref("transaction", lazy="joined"))

    @property
    def sign(self):
        return self._sign


class Trade(db.Model):
    """A Trade consists of one or more transactions"""
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    created_at = db.Column(db.DateTime, index=True, nullable=False)
    updated_at = db.Column(db.DateTime, index=True, nullable=False)
    entry_timestamp = db.Column(db.DateTime, index=True, nullable=False)
    entry_price = db.Column(db.Float, nullable=False)
    exit_timestamp = db.Column(db.DateTime, index=True)
    exit_price = db.Column(db.Float)
    shares = db.Column(db.Integer(), nullable=False)

    status_id = db.Column(db.ForeignKey('trade_status.id'))
    user_id = db.Column(db.ForeignKey('user.id'))
    position_id = db.Column(db.ForeignKey('trade_position.id'))
    strategy_id = db.Column(db.ForeignKey('trade_strategy.id'))
    account_id = db.Column(db.ForeignKey('trade_account.id'))
    security_id = db.Column(db.ForeignKey('security.id'))

    notes = db.relationship('TradeNote', backref=backref("trade", lazy="joined"))
    transactions = db.relationship('Transaction', backref=backref("trade", lazy="joined"))

    # def __init__(self, user, account, security, position, shares, entry_time, entry_price, strategy):
    #     # TODO: learn how to create multiple things at once in SQLAlchemy
    #
    #     self.user = user
    #     self.account = account
    #     self.security = security
    #     self.position = position
    #     self.shares = int(shares)
    #     self.entry_timestamp = entry_time
    #     self.entry_price = float(entry_price)
    #     self.strategy = strategy
    #
    #     now = datetime.utcnow()
    #     self.created_at = now
    #     self.updated_at = now
    #     self.set_uuid()

    def __repr__(self):
        # <Trade [+2 AYX @ 180.55] (85f94948-c1e0-5df1-bb65-068a31e1bcd4)>
        return '<Trade [{}{} {} @ {} ({})]>'.format(self.sign, self.shares, self.security.ticker, self.entry_price, self.uuid)

    def set_uuid(self):

        uuid_parents = [
            self.user.uuid,
            self.account.broker.uuid,
            self.account.uuid,
            self.security.uuid,
            self.entry_timestamp,
            self.entry_price,
            self.shares
        ]

        self.uuid = str(self.build_uuid(uuid_parents))

    def build_uuid(self, uuids):
        # This loop should build the final uuid based on the parent UUIDs in a cannonical way
        # TODO: make sure this works correctly
        temp_uuid = None
        for i, item in enumerate(uuids):
            if i == 0:
                temp_uuid = uuid.uuid5(NAMESPACE_GPFIX, str(item))
            else:
                temp_uuid = uuid.uuid5(temp_uuid, str(item))

        return temp_uuid

    def to_dict(self):
        data = {
            "uuid": self.uuid,
            "user": self.user.to_dict(),
            "_meta": {
                "self": "URL FOR THE TRADE"
            }
        }
        return data

    def create_from_dict(self, data):
        # ensure required fields are in the data
        required_fields = ['user', 'account', 'ticker', 'shares', 'entry_timestamp', 'entry_price']
        for field in required_fields:
            if field not in data:
                raise ValueError('{} is required'.format(field))

            if not data[field]:
                raise ValueError('{} cannot be empty!'.format(field))

        with db.session.no_autoflush:

            # TODO: handle UUID
            user = User.query.filter_by(username=data['user']).first()
            if user is None:
                raise ValueError('user does not exist')
            # TODO: Validate request for user
            # elif user is not current_user:
            #     raise ValueError('403 Forbidden')
            else:
                setattr(self, 'user', user)

            # TODO: handle UUID
            account = TradeAccount.query.filter_by(name=data['account']).first()
            if account is None:
                raise ValueError('account does not exist')
            else:
                setattr(self, 'account', account)

            security = Security.query.filter_by(ticker=data['ticker']).first()
            if security is None:
                # Add the new security
                security = Security()
                security.create_from_symbol(data['ticker'])

            setattr(self, 'security', security)

            # TODO: check for int type?
            setattr(self, 'shares', int(data['shares']))

            if self.shares > 0:
                self.position = TradePosition.query.filter_by(position="LONG").one()
            elif self.shares < 0:
                self.position = TradePosition.query.filter_by(position="SHORT").one()
            else:
                raise ValueError("Invalid entry for shares: {}".format(self.shares))

            if isinstance(data['entry_timestamp'].date(), date):
                setattr(self, 'entry_timestamp', data['entry_timestamp'])
            else:
                setattr(self, 'entry_timestamp', datetime.strptime(data['entry_timestamp'], TIME_FORMAT))

            setattr(self, 'entry_price', float(data['entry_price']))
            setattr(self, 'status', TradeStatus.query.filter_by(status='OPEN').one())

            # Optionals
            if 'exit_timestamp' in data:
                if 'exit_price' not in data:
                    raise ValueError("When exit_timestamp is present, exit_price is required")
                setattr(self, 'exit_timestamp', datetime.strptime(data['exit_timestamp'], TIME_FORMAT))
                setattr(self, 'status', TradeStatus.query.filter_by('CLOSED').one())

            if 'exit_price' in data:
                if 'exit_timestamp' not in data:
                    raise ValueError("When exit_price is present, exit_timestamp is required")
                setattr(self, 'exit_price', float(data['exit_price']))

            if 'strategy' in data:
                # TODO: filter_by(user_id=current_user.id)
                strategy = TradeStrategy.query.filter_by(user=self.user).filter_by(name=data["strategy"]).one()
                if strategy is None:
                    raise ValueError("Strategy [{}] does not exist".format(data['strategy']))
                setattr(self, 'strategy', strategy)

            timestamp = datetime.utcnow()

            for field in ['created_at', 'updated_at']:
                setattr(self, field, timestamp)

            self.set_uuid()

    def close_trade(self, trade_uuid, exit_timestamp, exit_price):
        trade = Trade.query.filter_by(uuid=trade_uuid).first()
        if trade is None:
            raise ValueError("Trade not found. UUID:{}".format(trade_uuid))

        if trade.status.status == "CLOSED":
            raise ValueError("Trade already closed. UUID:{}".format(trade_uuid))

        if trade.status.status != "OPEN":
            raise ValueError("Trade status is {}. {}".format(trade.status.status, trade))

        # zero out the shares
        trade.shares = trade.shares - trade.shares

        trade.exit_timestamp = exit_timestamp
        trade.exit_price = exit_price

        # change the trade status to "CLOSED"
        closed = TradeStatus.query.filter_by(status="CLOSED").first()
        setattr(trade, "status", closed.status)

        trade.updated_at = datetime.utcnow()

        # commit our changes
        db.session.commit()


class Security(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    ticker = db.Column(db.String(4), index=True, unique=True)
    full_name = db.Column(db.String(128), index=True, unique=True)

    exchange_id = db.Column(db.ForeignKey('exchange.id'))

    trades = db.relationship('Trade', backref=backref("security", lazy="joined"))

    # def __init__(self, ticker, full_name, exchange):
    #     self.ticker = ticker
    #     self.full_name = full_name
    #     self.exchange = exchange
    #     self.set_uuid()

    def __repr__(self):
        return '<Security {} - {} ({})>'.format(self.ticker, self.full_name, self.uuid)

    def set_uuid(self):
        # TODO generate based on exchange UUID
        self.uuid = str(uuid.uuid5(uuid.UUID(self.exchange.uuid), self.ticker))

    def create_from_symbol(self, ticker):
        # https://query2.finance.yahoo.com/v7/finance/options/AAPL
        r = requests.get("https://query2.finance.yahoo.com/v7/finance/options/{}".format(ticker))
        if r.ok:
            data = r.json()
        else:
            raise ValueError("Ticker [{}] not found".format(ticker))

        self.ticker = data['optionChain']['result'][0]['quote']['symbol']
        self.full_name = data['optionChain']['result'][0]['quote']['longName']

        exchange_name = data['optionChain']['result'][0]['quote']['fullExchangeName']

        if re.match(r'^Nasdaq.+$', exchange_name):
            exchange_name = "NASDAQ"

        exchange = Exchange.query.filter_by(name=exchange_name).first()
        if exchange is None:
            exchange = Exchange(name=exchange_name)

        setattr(self, 'exchange', exchange)

        self.set_uuid()


class Exchange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    name = db.Column(db.String(16), index=True, unique=True)

    securities = db.relationship('Security', backref=backref("exchange", lazy="joined"))

    def __init__(self, name):
        self.name = name
        self.set_uuid()

    def __repr__(self):
        return '<Exchange {} ({})>'.format(self.name, self.uuid)

    def set_uuid(self):
        self.uuid = str(uuid.uuid5(NAMESPACE_GPFIX, self.name))


class TradeStatus(db.Model):
    # OPEN, CLOSED
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    status = db.Column(db.String(32), index=True, unique=True)
    description = db.Column(db.String(256))

    trades = db.relationship('Trade', backref=backref("status", lazy="joined"))

    def __init__(self, status, description=None):
        self.status = status
        self.description = description
        self.set_uuid()

    def __repr__(self):
        return '<TradeStatus {} ({})>'.format(self.status, self.uuid)

    def set_uuid(self):
        self.uuid = str(uuid.uuid5(NAMESPACE_GPFIX, self.status))


class TradeAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    created_at = db.Column(db.DateTime, index=True, nullable=False)
    updated_at = db.Column(db.DateTime, index=True, nullable=False)
    name = db.Column(db.String(32), index=True, unique=True)

    account_type_id = db.Column(db.ForeignKey('trade_account_type.id'))
    broker_id = db.Column(db.ForeignKey('broker.id'))
    user_id = db.Column(db.ForeignKey('user.id'))

    trades = db.relationship('Trade', backref=backref("account", lazy="joined"))

    def __init__(self, name, account_type, broker, user):
        self.name = name
        self.type = account_type,
        self.broker = broker
        self.user = user
        now = datetime.utcnow()
        self.created_at = now
        self.updated_at = now
        self.set_uuid()

    def __repr__(self):
        return '<TradeAccount {} ({})>'.format(self.name, self.uuid)

    def set_uuid(self):
        self.uuid = str(uuid.uuid5(NAMESPACE_GPFIX, self.name))


class TradeAccountType(db.Model):
    # Cash / Margin
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    type = db.Column(db.String(32), index=True, unique=True)

    accounts = db.relationship('TradeAccount', backref=backref("account", lazy="joined"))

    def __init__(self, type):
        self.type = type
        self.set_uuid()

    def __repr__(self):
        return '<TradeAccountType {} ({})>'.format(self.type, self.uuid)

    def set_uuid(self):
        self.uuid = str(uuid.uuid5(NAMESPACE_GPFIX, self.type))


class Broker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    created_at = db.Column(db.DateTime, index=True, nullable=False)
    updated_at = db.Column(db.DateTime, index=True, nullable=False)
    name = db.Column(db.String(32), index=True, unique=True)

    accounts = db.relationship('TradeAccount', backref=backref("broker", lazy="joined"))

    def __init__(self, name):
        self.name = name
        now = datetime.utcnow()
        self.created_at = now
        self.updated_at = now
        self.set_uuid()

    def __repr__(self):
        return '<Broker {} ({})>'.format(self.name, self.uuid)

    def set_uuid(self):
        self.uuid = str(uuid.uuid5(NAMESPACE_GPFIX, self.name))


class TradePosition(db.Model):
    # LONG / SHORT
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    position = db.Column(db.String(32), index=True, unique=True)

    trades = db.relationship('Trade', backref=backref("position", lazy="joined"))

    def __init__(self, position):
        self.position = position
        self.set_uuid()

    def __repr__(self):
        return '<TradePosition {} ({})>'.format(self.position, self.uuid)

    def set_uuid(self):
        self.uuid = str(uuid.uuid5(NAMESPACE_GPFIX, self.position))


class TradeStrategy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    created_at = db.Column(db.DateTime, index=True, nullable=False)
    updated_at = db.Column(db.DateTime, index=True, nullable=False)
    name = db.Column(db.String(64), index=True, unique=True)
    description = db.Column(db.String(256), index=True, unique=True)

    user_id = db.Column(db.ForeignKey('user.id'))

    trades = db.relationship('Trade', backref=backref("strategy", lazy="joined"))

    def __init__(self, name, description, user):
        self.name = name
        self.description = description
        self.user = user
        now = datetime.utcnow()
        self.created_at = now
        self.updated_at = now
        self.set_uuid()

    def __repr__(self):
        return '<TradeStrategy {} ({})>'.format(self.name, self.uuid)

    def set_uuid(self):
        self.uuid = str(uuid.uuid5(NAMESPACE_GPFIX, self.name))


class TradeNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    created_at = db.Column(db.DateTime, index=True, nullable=False)
    updated_at = db.Column(db.DateTime, index=True, nullable=False)
    note = db.Column(db.String(256))

    trade_id = db.Column(db.ForeignKey('trade.id'))

    def __init__(self, note):
        self.note = note
        now = datetime.utcnow()
        self.created_at = now
        self.updated_at = now
        self.set_uuid()

    def __repr__(self):
        return '<TradeNote {}>'.format(self.uuid)

    def set_uuid(self):
        self.uuid = str(uuid.uuid5(NAMESPACE_GPFIX, self.note))


@login.user_loader
def load_user(id):
    return User.query.get(int(id))