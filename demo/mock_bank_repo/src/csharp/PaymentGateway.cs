using System;
using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;
using System.Transactions;
using Npgsql;

namespace BankingApp.Services.Payments
{
    /// <summary>
    /// Payment gateway service for EDB/Yugabyte (PostgreSQL-compatible) via Npgsql.
    /// Handles payment processing, queue management, and settlement operations.
    /// </summary>
    public class PaymentGateway
    {
        private readonly string _npgsqlConnectionString;
        private readonly ILogger<PaymentGateway> _logger;

        public PaymentGateway(
            string npgsqlConnectionString,
            ILogger<PaymentGateway> logger)
        {
            _npgsqlConnectionString = npgsqlConnectionString
                ?? throw new ArgumentNullException(nameof(npgsqlConnectionString));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // =====================================================================
        // VIOLATION METHODS - Intentional bad practices for scanner testing
        // =====================================================================

        /// <summary>
        /// Retrieves all pending payments using SELECT * -- exposes full payment data.
        /// </summary>
        public DataTable GetPendingPayments()
        {
            using (var connection = new NpgsqlConnection(_npgsqlConnectionString))
            {
                connection.Open();

                // VIOLATION: SELECT_STAR - Fetches all columns from PaymentQueue
                // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout on NpgsqlCommand
                var command = new NpgsqlCommand(
                    "SELECT * FROM PaymentQueue WHERE Status = 'Pending'",
                    connection);

                var adapter = new NpgsqlDataAdapter(command);
                var dataTable = new DataTable();
                adapter.Fill(dataTable);
                return dataTable;
            }
        }

        /// <summary>
        /// Looks up a payment using string interpolation -- SQL injection risk.
        /// </summary>
        public DataRow GetPaymentById(string paymentId)
        {
            using (var connection = new NpgsqlConnection(_npgsqlConnectionString))
            {
                connection.Open();

                // VIOLATION: SQL_INJECTION - String interpolation in SQL query
                // VIOLATION: SELECT_STAR - Fetches all columns
                // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout set
                var command = new NpgsqlCommand(
                    $"SELECT * FROM PaymentQueue WHERE PaymentId = '{paymentId}'",
                    connection);

                var adapter = new NpgsqlDataAdapter(command);
                var dataTable = new DataTable();
                adapter.Fill(dataTable);

                return dataTable.Rows.Count > 0 ? dataTable.Rows[0] : null;
            }
        }

        /// <summary>
        /// Settles payments one by one inside a loop -- poor performance.
        /// </summary>
        public void SettlePayments(List<PaymentSettlement> settlements)
        {
            using (var connection = new NpgsqlConnection(_npgsqlConnectionString))
            {
                connection.Open();

                // VIOLATION: EXECUTE_IN_LOOP - ExecuteNonQuery inside foreach loop
                foreach (var settlement in settlements)
                {
                    // VIOLATION: SQL_INJECTION - String interpolation in SQL
                    // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout set
                    var command = new NpgsqlCommand(
                        $"UPDATE PaymentQueue SET Status = 'Settled', SettlementDate = NOW(), " +
                        $"SettlementReference = '{settlement.ReferenceNumber}' " +
                        $"WHERE PaymentId = '{settlement.PaymentId}'",
                        connection);

                    // VIOLATION: EXECUTE_IN_LOOP - Individual ExecuteNonQuery per record
                    command.ExecuteNonQuery();

                    _logger.LogInformation("Settled payment {PaymentId}", settlement.PaymentId);
                }
            }
        }

        /// <summary>
        /// Processes a payment using TransactionScope without a timeout -- can hang indefinitely.
        /// </summary>
        public void ProcessPayment(PaymentRequest request)
        {
            // VIOLATION: TRANSACTION_SCOPE_NO_TIMEOUT - TransactionScope without explicit timeout
            using (var scope = new TransactionScope())
            {
                using (var connection = new NpgsqlConnection(_npgsqlConnectionString))
                {
                    connection.Open();

                    // VIOLATION: SQL_INJECTION - String interpolation
                    // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout set
                    var debitCommand = new NpgsqlCommand(
                        $"UPDATE Accounts SET Balance = Balance - {request.Amount} " +
                        $"WHERE AccountId = '{request.SourceAccountId}'",
                        connection);
                    debitCommand.ExecuteNonQuery();

                    var creditCommand = new NpgsqlCommand(
                        $"UPDATE Accounts SET Balance = Balance + {request.Amount} " +
                        $"WHERE AccountId = '{request.DestinationAccountId}'",
                        connection);
                    creditCommand.ExecuteNonQuery();

                    // VIOLATION: SQL_INJECTION - String interpolation in INSERT
                    var auditCommand = new NpgsqlCommand(
                        $"INSERT INTO PaymentQueue (PaymentId, SourceAccountId, DestAccountId, Amount, Status, CreatedDate) " +
                        $"VALUES ('{Guid.NewGuid()}', '{request.SourceAccountId}', '{request.DestinationAccountId}', " +
                        $"{request.Amount}, 'Completed', NOW())",
                        connection);
                    auditCommand.ExecuteNonQuery();
                }

                scope.Complete();
            }
        }

        /// <summary>
        /// Retrieves payment history with string concatenation for date filtering.
        /// </summary>
        public DataTable GetPaymentHistory(string accountId, string fromDate, string toDate)
        {
            using (var connection = new NpgsqlConnection(_npgsqlConnectionString))
            {
                connection.Open();

                // VIOLATION: SQL_INJECTION - String concatenation in SQL query
                // VIOLATION: SELECT_STAR - Fetches all columns
                // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout set
                string sql = "SELECT * FROM PaymentQueue WHERE "
                    + "(SourceAccountId = '" + accountId + "' OR DestAccountId = '" + accountId + "') "
                    + "AND CreatedDate BETWEEN '" + fromDate + "' AND '" + toDate + "'";

                var command = new NpgsqlCommand(sql, connection);

                var adapter = new NpgsqlDataAdapter(command);
                var dataTable = new DataTable();
                adapter.Fill(dataTable);
                return dataTable;
            }
        }

        // =====================================================================
        // CORRECT METHODS - Proper implementations for false-positive testing
        // =====================================================================

        /// <summary>
        /// Retrieves pending payments with explicit columns and parameterized query.
        /// </summary>
        public async Task<List<PendingPayment>> GetPendingPaymentsCorrectAsync()
        {
            using (var connection = new NpgsqlConnection(_npgsqlConnectionString))
            {
                await connection.OpenAsync();

                // CORRECT: Explicit columns, no string interpolation, CommandTimeout set
                var command = new NpgsqlCommand(
                    @"SELECT PaymentId, SourceAccountId, DestAccountId, Amount,
                             Status, CreatedDate, PaymentMethod
                      FROM PaymentQueue
                      WHERE Status = 'Pending'
                      ORDER BY CreatedDate ASC",
                    connection);

                command.CommandTimeout = 30;

                var results = new List<PendingPayment>();

                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        results.Add(new PendingPayment
                        {
                            PaymentId = reader.GetString(0),
                            SourceAccountId = reader.GetString(1),
                            DestinationAccountId = reader.GetString(2),
                            Amount = reader.GetDecimal(3),
                            Status = reader.GetString(4),
                            CreatedDate = reader.GetDateTime(5),
                            PaymentMethod = reader.GetString(6)
                        });
                    }
                }

                return results;
            }
        }

        /// <summary>
        /// Processes a payment using TransactionScope with proper timeout and parameterized queries.
        /// </summary>
        public async Task ProcessPaymentCorrectAsync(PaymentRequest request)
        {
            // CORRECT: TransactionScope with explicit timeout
            var txOptions = new TransactionOptions
            {
                IsolationLevel = System.Transactions.IsolationLevel.ReadCommitted,
                Timeout = TimeSpan.FromSeconds(30)
            };

            using (var scope = new TransactionScope(
                TransactionScopeOption.Required, txOptions, TransactionScopeAsyncFlowOption.Enabled))
            {
                using (var connection = new NpgsqlConnection(_npgsqlConnectionString))
                {
                    await connection.OpenAsync();

                    // CORRECT: Parameterized debit
                    var debitCommand = new NpgsqlCommand(
                        "UPDATE Accounts SET Balance = Balance - @Amount WHERE AccountId = @AccountId",
                        connection);
                    debitCommand.CommandTimeout = 15;
                    debitCommand.Parameters.AddWithValue("@Amount", request.Amount);
                    debitCommand.Parameters.AddWithValue("@AccountId", request.SourceAccountId);
                    await debitCommand.ExecuteNonQueryAsync();

                    // CORRECT: Parameterized credit
                    var creditCommand = new NpgsqlCommand(
                        "UPDATE Accounts SET Balance = Balance + @Amount WHERE AccountId = @AccountId",
                        connection);
                    creditCommand.CommandTimeout = 15;
                    creditCommand.Parameters.AddWithValue("@Amount", request.Amount);
                    creditCommand.Parameters.AddWithValue("@AccountId", request.DestinationAccountId);
                    await creditCommand.ExecuteNonQueryAsync();

                    // CORRECT: Parameterized audit insert
                    var auditCommand = new NpgsqlCommand(
                        @"INSERT INTO PaymentQueue
                            (PaymentId, SourceAccountId, DestAccountId, Amount, Status, CreatedDate)
                          VALUES
                            (@PaymentId, @SourceAccountId, @DestAccountId, @Amount, 'Completed', NOW())",
                        connection);
                    auditCommand.CommandTimeout = 15;
                    auditCommand.Parameters.AddWithValue("@PaymentId", Guid.NewGuid().ToString());
                    auditCommand.Parameters.AddWithValue("@SourceAccountId", request.SourceAccountId);
                    auditCommand.Parameters.AddWithValue("@DestAccountId", request.DestinationAccountId);
                    auditCommand.Parameters.AddWithValue("@Amount", request.Amount);
                    await auditCommand.ExecuteNonQueryAsync();
                }

                scope.Complete();
            }

            _logger.LogInformation("Payment processed: {Source} -> {Dest}, Amount: {Amount}",
                request.SourceAccountId, request.DestinationAccountId, request.Amount);
        }

        /// <summary>
        /// Batch settles payments using a single parameterized command in a transaction.
        /// </summary>
        public async Task SettlePaymentsBatchAsync(List<PaymentSettlement> settlements)
        {
            using (var connection = new NpgsqlConnection(_npgsqlConnectionString))
            {
                await connection.OpenAsync();

                // CORRECT: Batch operation with transaction and parameterized queries
                using (var transaction = await connection.BeginTransactionAsync())
                {
                    var command = new NpgsqlCommand(
                        @"UPDATE PaymentQueue
                          SET Status = 'Settled', SettlementDate = NOW(), SettlementReference = @Reference
                          WHERE PaymentId = @PaymentId",
                        connection, transaction);

                    command.CommandTimeout = 60;
                    command.Parameters.Add(new NpgsqlParameter("@Reference", NpgsqlTypes.NpgsqlDbType.Varchar));
                    command.Parameters.Add(new NpgsqlParameter("@PaymentId", NpgsqlTypes.NpgsqlDbType.Varchar));

                    command.Prepare();

                    foreach (var settlement in settlements)
                    {
                        command.Parameters["@Reference"].Value = settlement.ReferenceNumber;
                        command.Parameters["@PaymentId"].Value = settlement.PaymentId;
                        await command.ExecuteNonQueryAsync();
                    }

                    await transaction.CommitAsync();
                }
            }

            _logger.LogInformation("Batch settled {Count} payments", settlements.Count);
        }
    }

    // =====================================================================
    // Supporting model classes
    // =====================================================================

    public class PaymentRequest
    {
        public string SourceAccountId { get; set; }
        public string DestinationAccountId { get; set; }
        public decimal Amount { get; set; }
        public string PaymentMethod { get; set; }
    }

    public class PaymentSettlement
    {
        public string PaymentId { get; set; }
        public string ReferenceNumber { get; set; }
    }

    public class PendingPayment
    {
        public string PaymentId { get; set; }
        public string SourceAccountId { get; set; }
        public string DestinationAccountId { get; set; }
        public decimal Amount { get; set; }
        public string Status { get; set; }
        public DateTime CreatedDate { get; set; }
        public string PaymentMethod { get; set; }
    }
}
