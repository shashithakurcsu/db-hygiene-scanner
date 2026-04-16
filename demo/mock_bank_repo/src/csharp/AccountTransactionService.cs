using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace BankingApp.Services.Transactions
{
    /// <summary>
    /// Core account transaction service for MSSQL Server.
    /// Handles deposits, withdrawals, balance lookups, and transaction history.
    /// </summary>
    public class AccountTransactionService
    {
        private readonly string _connectionString;
        private readonly BankingDbContext _dbContext;
        private readonly ILogger<AccountTransactionService> _logger;

        public AccountTransactionService(
            string connectionString,
            BankingDbContext dbContext,
            ILogger<AccountTransactionService> logger)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
            _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // =====================================================================
        // VIOLATION METHODS - Intentional bad practices for scanner testing
        // =====================================================================

        /// <summary>
        /// Retrieves all account data using SELECT * -- wasteful and exposes sensitive columns.
        /// </summary>
        public DataTable GetAllAccounts()
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();

                // VIOLATION: SELECT_STAR - Fetches all columns including sensitive PII
                // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout set on SqlCommand
                var command = new SqlCommand("SELECT * FROM Accounts", connection);

                var adapter = new SqlDataAdapter(command);
                var dataTable = new DataTable();
                adapter.Fill(dataTable);
                return dataTable;
            }
        }

        /// <summary>
        /// Looks up an account by number using string concatenation -- SQL injection risk.
        /// </summary>
        public DataRow GetAccountByNumber(string accountNumber)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();

                // VIOLATION: SQL_INJECTION - String concatenation in SQL query
                // VIOLATION: SELECT_STAR - Fetches all columns unnecessarily
                // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout set
                var command = new SqlCommand(
                    "SELECT * FROM Accounts WHERE AccountNumber = '" + accountNumber + "'",
                    connection);

                var adapter = new SqlDataAdapter(command);
                var dataTable = new DataTable();
                adapter.Fill(dataTable);

                return dataTable.Rows.Count > 0 ? dataTable.Rows[0] : null;
            }
        }

        /// <summary>
        /// Posts a batch of transactions but calls SaveChanges() inside the loop.
        /// </summary>
        public async Task PostTransactionBatch(List<TransactionRecord> transactions)
        {
            // VIOLATION: SAVECHANGES_IN_LOOP - SaveChanges called per iteration instead of batch
            foreach (var transaction in transactions)
            {
                var entity = new TransactionEntity
                {
                    TransactionId = Guid.NewGuid(),
                    AccountId = transaction.AccountId,
                    Amount = transaction.Amount,
                    TransactionType = transaction.Type,
                    Description = transaction.Description,
                    TransactionDate = DateTime.UtcNow,
                    PostedDate = DateTime.UtcNow,
                    Status = "Posted"
                };

                _dbContext.Transactions.Add(entity);

                // VIOLATION: SAVECHANGES_IN_LOOP - Should be outside the loop
                await _dbContext.SaveChangesAsync();

                _logger.LogInformation("Posted transaction {TransactionId} for account {AccountId}",
                    entity.TransactionId, entity.AccountId);
            }
        }

        /// <summary>
        /// Searches transactions using string concatenation for the WHERE clause.
        /// </summary>
        public DataTable SearchTransactions(string accountId, string startDate, string endDate)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();

                // VIOLATION: SQL_INJECTION - String concatenation builds dynamic SQL
                // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout set
                string sql = "SELECT * FROM Transactions WHERE AccountId = '" + accountId + "'"
                    + " AND TransactionDate BETWEEN '" + startDate + "' AND '" + endDate + "'";

                var command = new SqlCommand(sql, connection);

                var adapter = new SqlDataAdapter(command);
                var dataTable = new DataTable();
                adapter.Fill(dataTable);
                return dataTable;
            }
        }

        // =====================================================================
        // CORRECT METHODS - Proper implementations for false-positive testing
        // =====================================================================

        /// <summary>
        /// Retrieves account summary using parameterized query with explicit column list.
        /// </summary>
        public async Task<AccountSummary> GetAccountSummaryAsync(string accountId)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                await connection.OpenAsync();

                // CORRECT: Explicit column list, parameterized query, CommandTimeout set
                var command = new SqlCommand(
                    @"SELECT AccountId, AccountNumber, AccountType, CurrentBalance, AvailableBalance,
                             AccountStatus, LastActivityDate
                      FROM Accounts
                      WHERE AccountId = @AccountId AND AccountStatus = 'Active'",
                    connection);

                command.CommandTimeout = 30;
                command.Parameters.AddWithValue("@AccountId", accountId);

                using (var reader = await command.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        return new AccountSummary
                        {
                            AccountId = reader.GetString(0),
                            AccountNumber = reader.GetString(1),
                            AccountType = reader.GetString(2),
                            CurrentBalance = reader.GetDecimal(3),
                            AvailableBalance = reader.GetDecimal(4),
                            Status = reader.GetString(5),
                            LastActivityDate = reader.GetDateTime(6)
                        };
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Posts a batch of transactions efficiently using a single SaveChanges call.
        /// </summary>
        public async Task PostTransactionBatchCorrect(List<TransactionRecord> transactions)
        {
            // CORRECT: All entities added first, single SaveChanges at the end
            foreach (var transaction in transactions)
            {
                var entity = new TransactionEntity
                {
                    TransactionId = Guid.NewGuid(),
                    AccountId = transaction.AccountId,
                    Amount = transaction.Amount,
                    TransactionType = transaction.Type,
                    Description = transaction.Description,
                    TransactionDate = DateTime.UtcNow,
                    PostedDate = DateTime.UtcNow,
                    Status = "Posted"
                };

                _dbContext.Transactions.Add(entity);
            }

            // CORRECT: Single SaveChanges outside the loop for batch efficiency
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Batch posted {Count} transactions successfully", transactions.Count);
        }

        /// <summary>
        /// Searches transactions using parameterized queries and explicit columns.
        /// </summary>
        public async Task<List<TransactionDetail>> SearchTransactionsCorrectAsync(
            string accountId, DateTime startDate, DateTime endDate)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                await connection.OpenAsync();

                // CORRECT: Parameterized query, explicit columns, CommandTimeout
                var command = new SqlCommand(
                    @"SELECT TransactionId, AccountId, Amount, TransactionType,
                             Description, TransactionDate, PostedDate, Status
                      FROM Transactions
                      WHERE AccountId = @AccountId
                        AND TransactionDate BETWEEN @StartDate AND @EndDate
                      ORDER BY TransactionDate DESC",
                    connection);

                command.CommandTimeout = 30;
                command.Parameters.AddWithValue("@AccountId", accountId);
                command.Parameters.AddWithValue("@StartDate", startDate);
                command.Parameters.AddWithValue("@EndDate", endDate);

                var results = new List<TransactionDetail>();

                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        results.Add(new TransactionDetail
                        {
                            TransactionId = reader.GetGuid(0).ToString(),
                            AccountId = reader.GetString(1),
                            Amount = reader.GetDecimal(2),
                            TransactionType = reader.GetString(3),
                            Description = reader.GetString(4),
                            TransactionDate = reader.GetDateTime(5),
                            PostedDate = reader.GetDateTime(6),
                            Status = reader.GetString(7)
                        });
                    }
                }

                return results;
            }
        }
    }

    // =====================================================================
    // Supporting model classes
    // =====================================================================

    public class TransactionRecord
    {
        public string AccountId { get; set; }
        public decimal Amount { get; set; }
        public string Type { get; set; }
        public string Description { get; set; }
    }

    public class AccountSummary
    {
        public string AccountId { get; set; }
        public string AccountNumber { get; set; }
        public string AccountType { get; set; }
        public decimal CurrentBalance { get; set; }
        public decimal AvailableBalance { get; set; }
        public string Status { get; set; }
        public DateTime LastActivityDate { get; set; }
    }

    public class TransactionDetail
    {
        public string TransactionId { get; set; }
        public string AccountId { get; set; }
        public decimal Amount { get; set; }
        public string TransactionType { get; set; }
        public string Description { get; set; }
        public DateTime TransactionDate { get; set; }
        public DateTime PostedDate { get; set; }
        public string Status { get; set; }
    }

    public class TransactionEntity
    {
        public Guid TransactionId { get; set; }
        public string AccountId { get; set; }
        public decimal Amount { get; set; }
        public string TransactionType { get; set; }
        public string Description { get; set; }
        public DateTime TransactionDate { get; set; }
        public DateTime PostedDate { get; set; }
        public string Status { get; set; }
    }
}
