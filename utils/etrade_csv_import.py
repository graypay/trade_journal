import csv
from datetime import datetime
import pandas as pd
import app
from app.models import *
from app import db
from sqlalchemy.exc import IntegrityError

app_instance = app.create_app()
app_instance.app_context().push()
etrade_df = pd.read_csv("../data/Margin_Txn_History.csv", skiprows=[0, 1, 3])



for row in etrade_df.itertuples():
    # print(row)
    # print(row.TransactionDate, row.Symbol)

    if row.SecurityType != "EQ":
        # print("Skipping row:{}".format(row))
        continue

    if row.TransactionType == "Bought":
        # Open a new trade

    if row.TransactionType == "Sold":
        # close/split the original trade
        

    if row.TransactionType not in ["Bought", "Sold"]:
        # print("Skipping row:{}".format(row))
        continue

    txn_date = datetime.strptime(row.TransactionDate, "%m/%d/%y")

    trade_data = {
        "user": "gpaynter",
        "account": "ET-6012",
        "ticker": row.Symbol,
        "entry_timestamp": txn_date,
        "entry_price": row.Price,
        "shares": int(row.Quantity)
    }

    with db.session.no_autoflush:

        trade = Trade()
        try:
            trade.create_from_dict(trade_data)
        except ValueError as e:
            print(e)

        trd = Trade.query.filter_by(uuid=trade.uuid).first()
        if trd is not None:
            print("{} already exists, skipping...".format(trade))
            db.session.rollback()
            continue

        print("Adding: {}".format(trade))
        db.session.add(trade)

        try:
            db.session.commit()
        except IntegrityError as e:
            print("{} already exists, skipping...".format(trade))
            db.session.rollback()
            continue

print("DONE")