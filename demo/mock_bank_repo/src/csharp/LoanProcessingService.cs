using System;
using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;
using Oracle.ManagedDataAccess.Client;

namespace BankingApp.Services.Lending
{
    /// <summary>
    /// Loan processing service for Oracle Database backend.
    /// Handles loan applications, underwriting lookups, and disbursement processing.
    /// </summary>
    public class LoanProcessingService
    {
        private readonly string _oracleConnectionString;
        private readonly ILogger<LoanProcessingService> _logger;

        public LoanProcessingService(
            string oracleConnectionString,
            ILogger<LoanProcessingService> logger)
        {
            _oracleConnectionString = oracleConnectionString
                ?? throw new ArgumentNullException(nameof(oracleConnectionString));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // =====================================================================
        // VIOLATION METHODS - Intentional bad practices for scanner testing
        // =====================================================================

        /// <summary>
        /// Retrieves all loan applications using SELECT * -- exposes full schema.
        /// </summary>
        public DataTable GetAllLoanApplications()
        {
            using (var connection = new OracleConnection(_oracleConnectionString))
            {
                connection.Open();

                // VIOLATION: SELECT_STAR - Fetches all columns including SSN, income, etc.
                // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout on OracleCommand
                var command = new OracleCommand(
                    "SELECT * FROM LoanApplications WHERE ApplicationStatus = 'Pending'",
                    connection);

                var adapter = new OracleDataAdapter(command);
                var dataTable = new DataTable();
                adapter.Fill(dataTable);
                return dataTable;
            }
        }

        /// <summary>
        /// Looks up a loan application using string.Format -- SQL injection risk.
        /// </summary>
        public DataRow GetLoanApplicationById(string applicationId)
        {
            using (var connection = new OracleConnection(_oracleConnectionString))
            {
                connection.Open();

                // VIOLATION: SQL_INJECTION - string.Format used for SQL construction
                // VIOLATION: SELECT_STAR - Fetches all columns
                // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout set
                string sql = string.Format(
                    "SELECT * FROM LoanApplications WHERE ApplicationId = '{0}'",
                    applicationId);

                var command = new OracleCommand(sql, connection);

                var adapter = new OracleDataAdapter(command);
                var dataTable = new DataTable();
                adapter.Fill(dataTable);

                return dataTable.Rows.Count > 0 ? dataTable.Rows[0] : null;
            }
        }

        /// <summary>
        /// Inserts disbursement records one at a time inside a loop -- no batching.
        /// </summary>
        public void ProcessDisbursements(List<DisbursementRecord> disbursements)
        {
            using (var connection = new OracleConnection(_oracleConnectionString))
            {
                connection.Open();

                // VIOLATION: INSERT_IN_LOOP - Individual INSERT per iteration, no batching
                foreach (var disbursement in disbursements)
                {
                    // VIOLATION: SQL_INJECTION - string.Format in Oracle SQL
                    // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout set
                    string sql = string.Format(
                        @"INSERT INTO LoanDisbursements
                            (DisbursementId, LoanId, Amount, DisbursementDate, AccountNumber, Status)
                          VALUES
                            ('{0}', '{1}', {2}, SYSDATE, '{3}', 'Processed')",
                        Guid.NewGuid(),
                        disbursement.LoanId,
                        disbursement.Amount,
                        disbursement.TargetAccountNumber);

                    // VIOLATION: INSERT_IN_LOOP - ExecuteNonQuery called per record
                    var command = new OracleCommand(sql, connection);
                    command.ExecuteNonQuery();

                    _logger.LogInformation("Disbursed {Amount} for loan {LoanId}",
                        disbursement.Amount, disbursement.LoanId);
                }
            }
        }

        /// <summary>
        /// Updates loan statuses individually using string concatenation.
        /// </summary>
        public void UpdateLoanStatuses(List<LoanStatusUpdate> updates)
        {
            using (var connection = new OracleConnection(_oracleConnectionString))
            {
                connection.Open();

                // VIOLATION: INSERT_IN_LOOP - Individual UPDATE per iteration
                foreach (var update in updates)
                {
                    // VIOLATION: SQL_INJECTION - String concatenation in Oracle SQL
                    // VIOLATION: MISSING_COMMAND_TIMEOUT - No CommandTimeout set
                    string sql = "UPDATE LoanApplications SET ApplicationStatus = '" + update.NewStatus + "'"
                        + ", LastModifiedDate = SYSDATE"
                        + ", UnderwriterNotes = '" + update.Notes + "'"
                        + " WHERE ApplicationId = '" + update.ApplicationId + "'";

                    var command = new OracleCommand(sql, connection);
                    command.ExecuteNonQuery();
                }
            }
        }

        // =====================================================================
        // CORRECT METHODS - Proper implementations for false-positive testing
        // =====================================================================

        /// <summary>
        /// Retrieves loan application with parameterized query and explicit columns.
        /// </summary>
        public async Task<LoanApplication> GetLoanApplicationCorrectAsync(string applicationId)
        {
            using (var connection = new OracleConnection(_oracleConnectionString))
            {
                await connection.OpenAsync();

                // CORRECT: Explicit columns, parameterized query, CommandTimeout set
                var command = new OracleCommand(
                    @"SELECT ApplicationId, ApplicantName, LoanType, RequestedAmount,
                             InterestRate, TermMonths, ApplicationStatus, SubmissionDate,
                             CreditScore, DebtToIncomeRatio
                      FROM LoanApplications
                      WHERE ApplicationId = :ApplicationId",
                    connection);

                command.CommandTimeout = 30;
                command.Parameters.Add(new OracleParameter("ApplicationId", applicationId));

                using (var reader = await command.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        return new LoanApplication
                        {
                            ApplicationId = reader.GetString(0),
                            ApplicantName = reader.GetString(1),
                            LoanType = reader.GetString(2),
                            RequestedAmount = reader.GetDecimal(3),
                            InterestRate = reader.GetDecimal(4),
                            TermMonths = reader.GetInt32(5),
                            Status = reader.GetString(6),
                            SubmissionDate = reader.GetDateTime(7),
                            CreditScore = reader.GetInt32(8),
                            DebtToIncomeRatio = reader.GetDecimal(9)
                        };
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Batch inserts disbursements using OracleBulkCopy for efficiency.
        /// </summary>
        public async Task ProcessDisbursementsBatchAsync(List<DisbursementRecord> disbursements)
        {
            using (var connection = new OracleConnection(_oracleConnectionString))
            {
                await connection.OpenAsync();

                // CORRECT: Parameterized batch insert with transaction
                using (var transaction = connection.BeginTransaction())
                {
                    var command = new OracleCommand(
                        @"INSERT INTO LoanDisbursements
                            (DisbursementId, LoanId, Amount, DisbursementDate, AccountNumber, Status)
                          VALUES
                            (:DisbursementId, :LoanId, :Amount, SYSDATE, :AccountNumber, 'Processed')",
                        connection);

                    command.CommandTimeout = 60;

                    command.Parameters.Add(new OracleParameter("DisbursementId", OracleDbType.Varchar2));
                    command.Parameters.Add(new OracleParameter("LoanId", OracleDbType.Varchar2));
                    command.Parameters.Add(new OracleParameter("Amount", OracleDbType.Decimal));
                    command.Parameters.Add(new OracleParameter("AccountNumber", OracleDbType.Varchar2));

                    // CORRECT: Prepare once, execute many with different parameter values
                    command.Prepare();

                    foreach (var disbursement in disbursements)
                    {
                        command.Parameters["DisbursementId"].Value = Guid.NewGuid().ToString();
                        command.Parameters["LoanId"].Value = disbursement.LoanId;
                        command.Parameters["Amount"].Value = disbursement.Amount;
                        command.Parameters["AccountNumber"].Value = disbursement.TargetAccountNumber;

                        await command.ExecuteNonQueryAsync();
                    }

                    transaction.Commit();
                }
            }

            _logger.LogInformation("Batch disbursed {Count} loans successfully", disbursements.Count);
        }

        /// <summary>
        /// Retrieves pending applications with pagination -- correct pattern.
        /// </summary>
        public async Task<List<LoanApplication>> GetPendingApplicationsPagedAsync(int page, int pageSize)
        {
            using (var connection = new OracleConnection(_oracleConnectionString))
            {
                await connection.OpenAsync();

                // CORRECT: Explicit columns, parameterized, with pagination
                var command = new OracleCommand(
                    @"SELECT ApplicationId, ApplicantName, LoanType, RequestedAmount,
                             InterestRate, TermMonths, ApplicationStatus, SubmissionDate,
                             CreditScore, DebtToIncomeRatio
                      FROM LoanApplications
                      WHERE ApplicationStatus = 'Pending'
                      ORDER BY SubmissionDate ASC
                      OFFSET :Offset ROWS FETCH NEXT :PageSize ROWS ONLY",
                    connection);

                command.CommandTimeout = 30;
                command.Parameters.Add(new OracleParameter("Offset", (page - 1) * pageSize));
                command.Parameters.Add(new OracleParameter("PageSize", pageSize));

                var results = new List<LoanApplication>();

                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        results.Add(new LoanApplication
                        {
                            ApplicationId = reader.GetString(0),
                            ApplicantName = reader.GetString(1),
                            LoanType = reader.GetString(2),
                            RequestedAmount = reader.GetDecimal(3),
                            InterestRate = reader.GetDecimal(4),
                            TermMonths = reader.GetInt32(5),
                            Status = reader.GetString(6),
                            SubmissionDate = reader.GetDateTime(7),
                            CreditScore = reader.GetInt32(8),
                            DebtToIncomeRatio = reader.GetDecimal(9)
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

    public class DisbursementRecord
    {
        public string LoanId { get; set; }
        public decimal Amount { get; set; }
        public string TargetAccountNumber { get; set; }
    }

    public class LoanStatusUpdate
    {
        public string ApplicationId { get; set; }
        public string NewStatus { get; set; }
        public string Notes { get; set; }
    }

    public class LoanApplication
    {
        public string ApplicationId { get; set; }
        public string ApplicantName { get; set; }
        public string LoanType { get; set; }
        public decimal RequestedAmount { get; set; }
        public decimal InterestRate { get; set; }
        public int TermMonths { get; set; }
        public string Status { get; set; }
        public DateTime SubmissionDate { get; set; }
        public int CreditScore { get; set; }
        public decimal DebtToIncomeRatio { get; set; }
    }
}
