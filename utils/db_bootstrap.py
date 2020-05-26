import app
app_instance = app.create_app()

# from app import db
from app.models import *
from sqlalchemy.exc import IntegrityError

app_instance.app_context().push()


def do_or_do_not_there_is_no_try():
    try:
        db.session.commit()
    except IntegrityError as e:
        print("Rolling back transaction: {}".format(e))
        db.session.rollback()


# add exchanges
print("Adding Exchanges")
exchanges_to_add = ["NYSE", "NASDAQ"]

for exchange in exchanges_to_add:
    ex = Exchange.query.filter_by(name=exchange).first()
    if ex is not None:
        print("{} already exists, skipping...".format(exchange))
        continue

    ex = Exchange(name=exchange)
    print("Adding {}".format(ex))
    db.session.add(ex)
    do_or_do_not_there_is_no_try()


# add brokers
print("Adding Brokers")
brokers_to_add = ["E*TRADE", "Webull"]

for broker in brokers_to_add:

    br = Broker.query.filter_by(name=broker).first()
    if br is not None:
        print("{} already exists, skipping...".format(broker))
        continue

    br = Broker(name=broker)
    print("Adding {}".format(br))
    db.session.add(br)
    do_or_do_not_there_is_no_try()


# add users
print("Adding Users")

users_to_add = []
gpaynter = {
    "username": "gpaynter",
    "email": "grayson.paynter@gmail.com",
    "password": "test"
}
users_to_add.append(gpaynter)

for user in users_to_add:
    u = User.query.filter_by(username=user['username']).first()
    if u is not None:
        print("Username {} already exists, skipping...".format(user['username']))
        continue

    u = User.query.filter_by(email=user['email']).first()
    if u is not None:
        print("Email {} already exists, skipping...".format(user['email']))
        continue

    u = User(
        username=user['username'],
        email=user['email'],
        password=user['password']
    )

    print("Adding {}".format(u))
    db.session.add(u)
    do_or_do_not_there_is_no_try()


# add account types
print("Adding Account Types")
account_types_to_add = ["Cash", "Margin"]

for account_type in account_types_to_add:
    at = TradeAccountType.query.filter_by(type=account_type).first()
    if at is not None:
        print("{} already exists, skipping...".format(account_type))
        continue

    at = TradeAccountType(type=account_type)
    print("Adding {}".format(at))
    db.session.add(at)
    do_or_do_not_there_is_no_try()


# add accounts
print("Adding Accounts")
accounts_to_add = []
et_0715 = {
    "name": "ET-0715",
    "account_type": "Cash",
    "broker": "E*TRADE",
    "user": "gpaynter"
}
accounts_to_add.append(et_0715)
et_6012 = {
    "name": "ET-6012",
    "account_type": "Margin",
    "broker": "E*TRADE",
    "user": "gpaynter"
}
accounts_to_add.append(et_6012)
wb_5493 = {
    "name": "WB-5493",
    "account_type": "Cash",
    "broker": "Webull",
    "user": "gpaynter"
}
accounts_to_add.append(wb_5493)

for account in accounts_to_add:
    acct = TradeAccount.query.filter_by(user=User.query.filter_by(username=account['user']).first()).filter_by(name=account['name']).first()
    if acct is not None:
        print("{} already exists, skipping...".format(account))
        continue

    # TODO: if something here doesn't exist, it should be added
    acct = TradeAccount(
        name=account['name'],
        account_type=TradeAccountType.query.filter_by(type=account['account_type']).one(),
        broker=Broker.query.filter_by(name=account['broker']).one(),
        user=User.query.filter_by(username=account['user']).one()
    )

    print("Adding {}".format(acct))
    db.session.add(acct)
    do_or_do_not_there_is_no_try()


# add trade statuses
print("Adding Trade Statuses")
trade_statuses_to_add = ["OPEN", "CLOSED"]

for trade_status in trade_statuses_to_add:
    ts = TradeStatus.query.filter_by(status=trade_status).first()
    if ts is not None:
        print("{} already exists, skipping...".format(trade_status))
        continue

    ts = TradeStatus(status=trade_status)
    print("Adding {}".format(ts))
    db.session.add(ts)
    do_or_do_not_there_is_no_try()


# add strategies
print("Adding Strategies")
strategies_to_add = []
gpaynter = User.query.filter_by(username="gpaynter").first()
swingtrader = {
    "name": "SwingTrader",
    "description": "Short Term trades based on technical analysis.",
    "user": gpaynter
}
strategies_to_add.append(swingtrader)

buy_and_hold = {
    "name": "Buy & Hold",
    "description": "Long term trades",
    "user": gpaynter
}
strategies_to_add.append(buy_and_hold)

fool = {
    "name": "Fool",
    "description": "The Motley Fool Suggestions",
    "user": gpaynter
}
strategies_to_add.append(fool)

dividend = {
    "name": "Dividend",
    "description": "Holding just for the dividend",
    "user": gpaynter
}
strategies_to_add.append(dividend)

cm_ult_macd_mtf = {
    "name": "CM_Ult_MacD_MTF",
    "description": "Day Trade based on the Chris Moody MACD oscillator on TradingView",
    "user": gpaynter
}
strategies_to_add.append(cm_ult_macd_mtf)

for strategy in strategies_to_add:
    strat = TradeStrategy.query.filter_by(name=strategy['name']).first()
    if strat is not None:
        print("Strategy {} for user {} already exists, skipping...".format(strategy['name'], strategy['user'].username))
        continue

    strat = TradeStrategy(name=strategy['name'], description=strategy['description'], user=strategy['user'])
    print("Adding {}".format(strat))
    db.session.add(strat)
    do_or_do_not_there_is_no_try()

# add positions
print("Adding Positions")
positions_to_add = ["LONG", "SHORT"]
for position in positions_to_add:
    pos = TradePosition.query.filter_by(position=position).first()
    if pos is not None:
        print("{} already exists, skipping...".format(trade_status))
        continue

    pos = TradePosition(position=position)
    print("Adding {}".format(pos))
    db.session.add(pos)
    do_or_do_not_there_is_no_try()

# add trades
print("Adding Trades")
trades_to_add = []
gpaynter = User.query.filter_by(username="gpaynter").first()
ayx = Security.query.filter_by(ticker="AYX").first()
if ayx is None:
    ayx = Security(ticker="AYX", full_name="Alteryx, Inc.", exchange=Exchange.query.filter_by(name="NYSE").first())
    print("Adding {}".format(ayx))
    db.session.add(ayx)
    do_or_do_not_there_is_no_try()

time_format = "%m/%d/%y %I:%M:%S %p"

t1 = Trade(
    user=gpaynter,
    account=TradeAccount.query.filter_by(user=gpaynter).filter_by(name="ET-6012").first(),
    security=ayx,
    position=TradePosition.query.filter_by(position="LONG").first(),
    shares=8,
    entry_time=datetime.strptime("05/15/20 11:22:38 AM", time_format),
    entry_price=128.53,
    strategy=TradeStrategy.query.filter_by(name="SwingTrader").first()
)
trades_to_add.append(t1)

for trade in trades_to_add:
    print("Adding {}".format(trade))
    db.session.add(trade)
    do_or_do_not_there_is_no_try()

print("Done")


