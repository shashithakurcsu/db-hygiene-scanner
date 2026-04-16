from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

class AccountQuery:
    def __init__(self, oracle_connection_string):
        self.engine = create_engine(oracle_connection_string)
        self.Session = sessionmaker(bind=self.engine)

    # VIOLATION: SELECT_STAR
    def get_all_accounts(self):
        session = self.Session()
        query = text("SELECT * FROM Accounts")
        accounts = session.execute(query).fetchall()
        session.close()
        return accounts

    # VIOLATION: SQL_INJECTION (string concatenation with text())
    def get_account_by_number(self, account_number):
        session = self.Session()
        query_str = "SELECT * FROM Accounts WHERE account_number = '" + account_number + "'"
        query = text(query_str)
        result = session.execute(query).fetchone()
        session.close()
        return result

    # VIOLATION: UNBATCHED_UPDATES (session.add in loop)
    def save_account_batch(self, accounts):
        session = self.Session()
        for account in accounts:
            session.add(account)
        session.commit()
        session.close()
