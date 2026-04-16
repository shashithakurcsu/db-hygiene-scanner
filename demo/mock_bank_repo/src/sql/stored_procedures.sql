-- VIOLATION: SELECT_STAR
CREATE PROCEDURE sp_GetActiveAccounts
    @Status NVARCHAR(50)
AS
BEGIN
    SELECT * FROM Accounts WHERE Status = @Status
END
GO

-- VIOLATION: SQL_INJECTION (dynamic SQL with concatenation)
CREATE PROCEDURE sp_GetAccountByNumber
    @AccountNumber NVARCHAR(50)
AS
BEGIN
    DECLARE @SQL NVARCHAR(MAX)
    SET @SQL = 'SELECT * FROM Accounts WHERE AccountNumber = ''' + @AccountNumber + ''''
    EXEC(@SQL)
END
GO

-- VIOLATION: MISSING_TRY_CATCH + BEGIN TRANSACTION without isolation
CREATE PROCEDURE sp_PostTransactions
    @TransactionCount INT
AS
BEGIN
    BEGIN TRANSACTION
    INSERT INTO PostedTransactions (TransactionId, Amount, PostDate)
    SELECT TOP (@TransactionCount) * FROM StagedTransactions
    COMMIT TRANSACTION
END
GO

-- VIOLATION: CURSOR without FAST_FORWARD
CREATE PROCEDURE sp_ProcessLoanBatch
AS
BEGIN
    DECLARE cur CURSOR FOR
        SELECT LoanId, AppliedAmount FROM LoanApplications WHERE Status = 'PENDING'
    OPEN cur
    DECLARE @LoanId NVARCHAR(50), @Amount DECIMAL(18,2)
    FETCH NEXT FROM cur INTO @LoanId, @Amount
    WHILE @@FETCH_STATUS = 0
    BEGIN
        UPDATE LoanApplications SET Status = 'PROCESSING' WHERE LoanId = @LoanId
        FETCH NEXT FROM cur INTO @LoanId, @Amount
    END
    CLOSE cur
    DEALLOCATE cur
END
GO

-- ===== CORRECT EXAMPLES =====
CREATE PROCEDURE sp_GetActiveAccountsCorrect
    @Status NVARCHAR(50)
AS
BEGIN
    SELECT AccountId, AccountNumber, CustomerId, Balance, Status
    FROM Accounts WHERE Status = @Status
END
GO
