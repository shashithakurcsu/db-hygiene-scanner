from pymongo import MongoClient, ReadPreference
from pymongo.errors import DuplicateKeyError

class MongoOperations:
    def __init__(self, mongo_uri):
        # VIOLATION: NO_READ_PREFERENCE (no ReadPreference)
        self.client = MongoClient(mongo_uri)
        self.db = self.client['bank_db']
        self.accounts = self.db['accounts']

    # VIOLATION: NO_READ_PREFERENCE / SELECT_STAR
    def get_account_balance(self, account_id):
        account = self.accounts.find_one({'account_id': account_id})
        return account

    # VIOLATION: NO_READ_PREFERENCE
    def get_customer_accounts(self, customer_id):
        accounts = list(self.accounts.find({'customer_id': customer_id}))
        return accounts

    # VIOLATION: NO_BULK_WRITE (individual insert per loop)
    def save_account_batch(self, accounts):
        for account in accounts:
            try:
                self.accounts.insert_one(account)
            except DuplicateKeyError:
                pass

    # Correct examples
    def get_account_balance_correct(self, account_id):
        projection = {'account_id': 1, 'balance': 1, 'status': 1}
        return self.accounts.find_one({'account_id': account_id}, projection)

    def get_customer_accounts_correct(self, customer_id):
        client = MongoClient("mongodb://localhost:27017", read_preference=ReadPreference.SECONDARY_PREFERRED)
        db = client['bank_db']
        return list(db['accounts'].find({'customer_id': customer_id}))

    def save_account_batch_correct(self, accounts):
        from pymongo import InsertOne
        operations = [InsertOne(account) for account in accounts]
        self.accounts.bulk_write(operations, ordered=False)
