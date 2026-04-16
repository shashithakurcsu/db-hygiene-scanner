-- Clean DDL with no hygiene violations
-- The scanner should NOT flag anything in this file
CREATE TABLE Accounts (
    AccountId NVARCHAR(50) PRIMARY KEY,
    AccountNumber NVARCHAR(50) NOT NULL UNIQUE,
    CustomerId NVARCHAR(50) NOT NULL,
    Balance DECIMAL(18,2) NOT NULL,
    Status NVARCHAR(50) NOT NULL,
    CreatedDate DATETIME NOT NULL DEFAULT GETDATE(),
    ModifiedDate DATETIME NOT NULL DEFAULT GETDATE()
)
GO

CREATE TABLE Transactions (
    TransactionId NVARCHAR(50) PRIMARY KEY,
    AccountId NVARCHAR(50) NOT NULL,
    Amount DECIMAL(18,2) NOT NULL,
    TransactionType NVARCHAR(50) NOT NULL,
    PostDate DATETIME NOT NULL,
    FOREIGN KEY (AccountId) REFERENCES Accounts(AccountId)
)
GO

CREATE INDEX idx_Accounts_Status ON Accounts(Status)
GO
CREATE INDEX idx_Transactions_AccountId ON Transactions(AccountId)
GO
