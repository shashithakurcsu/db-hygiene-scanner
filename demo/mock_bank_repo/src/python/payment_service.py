import psycopg2

class PaymentService:
    def __init__(self, connection_string):
        # VIOLATION: NO_TIMEOUT (no connect_timeout parameter)
        self.connection_string = connection_string

    def get_pending_payments(self):
        # VIOLATION: SELECT_STAR
        conn = psycopg2.connect(self.connection_string)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM payments WHERE status = 'PENDING'")
        payments = cursor.fetchall()
        cursor.close()
        conn.close()
        return payments

    # VIOLATION: SQL_INJECTION (f-string in execute)
    def get_payment_by_id(self, payment_id):
        conn = psycopg2.connect(self.connection_string)
        cursor = conn.cursor()
        query = f"SELECT * FROM payments WHERE payment_id = {payment_id}"
        cursor.execute(query)
        payment = cursor.fetchone()
        cursor.close()
        conn.close()
        return payment

    # VIOLATION: UNBATCHED_UPDATES (individual execute calls)
    def process_payment_batch(self, payments):
        conn = psycopg2.connect(self.connection_string)
        cursor = conn.cursor()
        for payment in payments:
            cursor.execute(
                "UPDATE payments SET status = %s WHERE payment_id = %s",
                ('PROCESSED', payment['id'])
            )
        conn.commit()
        cursor.close()
        conn.close()

    # Correct example
    def process_payment_batch_correct(self, payments):
        conn = psycopg2.connect(self.connection_string, connect_timeout=10)
        cursor = conn.cursor()
        data = [(payment['id'], 'PROCESSED') for payment in payments]
        cursor.executemany("UPDATE payments SET status = %s WHERE payment_id = %s", data)
        conn.commit()
        cursor.close()
        conn.close()
