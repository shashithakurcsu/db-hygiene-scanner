-- VIOLATION: SELECT_STAR in cursor + Individual INSERT in loop
CREATE OR REPLACE PROCEDURE migrate_to_new_schema AS
    CURSOR account_cursor IS
        SELECT * FROM accounts_old;
    TYPE account_table_type IS TABLE OF account_cursor%ROWTYPE INDEX BY PLS_INTEGER;
    accounts account_table_type;
BEGIN
    OPEN account_cursor;
    FETCH account_cursor BULK COLLECT INTO accounts;
    CLOSE account_cursor;
    FOR i IN 1..accounts.COUNT
    LOOP
        INSERT INTO accounts_new (account_id, customer_id, balance, status)
        VALUES (accounts(i).account_id, accounts(i).customer_id, accounts(i).balance, accounts(i).status);
        IF i MOD 100 = 0 THEN COMMIT; END IF;
    END LOOP;
    COMMIT;
END migrate_to_new_schema;
/

-- VIOLATION: EXECUTE IMMEDIATE with string concatenation
CREATE OR REPLACE PROCEDURE migrate_transactions_with_dynamic_sql (p_source_table VARCHAR2) AS
    v_sql VARCHAR2(1000);
BEGIN
    v_sql := 'INSERT INTO transactions_new SELECT * FROM ' || p_source_table;
    EXECUTE IMMEDIATE v_sql;
    COMMIT;
END migrate_transactions_with_dynamic_sql;
/
