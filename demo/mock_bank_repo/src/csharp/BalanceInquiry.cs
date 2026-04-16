using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MongoDB.Bson;
using MongoDB.Driver;

namespace BankingApp.Services.Inquiry
{
    /// <summary>
    /// Balance inquiry service backed by MongoDB.
    /// Handles real-time balance lookups, account snapshots, and balance history.
    /// </summary>
    public class BalanceInquiry
    {
        private readonly IMongoClient _mongoClient;
        private readonly IMongoDatabase _database;
        private readonly ILogger<BalanceInquiry> _logger;

        // =====================================================================
        // VIOLATION CONSTRUCTOR - Missing ReadPreference on MongoClient
        // =====================================================================

        /// <summary>
        /// Initializes MongoDB client without specifying ReadPreference.
        /// </summary>
        public BalanceInquiry(string connectionString, ILogger<BalanceInquiry> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            // VIOLATION: MONGO_NO_READ_PREFERENCE - MongoClient created without ReadPreference
            // In a replica set, this defaults to Primary which may not be desired for read-heavy workloads
            _mongoClient = new MongoClient(connectionString);
            _database = _mongoClient.GetDatabase("banking_db");
        }

        // =====================================================================
        // VIOLATION METHODS - Intentional bad practices for scanner testing
        // =====================================================================

        /// <summary>
        /// Fetches account balance without projection -- returns all fields (like SELECT *).
        /// </summary>
        public async Task<BsonDocument> GetAccountBalance(string accountId)
        {
            var collection = _database.GetCollection<BsonDocument>("AccountBalances");

            // VIOLATION: MONGO_NO_PROJECTION - Find without projection returns all fields
            // This is the MongoDB equivalent of SELECT * -- returns SSN, internal flags, etc.
            var filter = Builders<BsonDocument>.Filter.Eq("AccountId", accountId);
            var result = await collection.Find(filter).FirstOrDefaultAsync();

            return result;
        }

        /// <summary>
        /// Retrieves all balance snapshots for an account without projection.
        /// </summary>
        public async Task<List<BsonDocument>> GetBalanceHistory(string accountId)
        {
            // VIOLATION: MONGO_NO_READ_PREFERENCE - Collection accessed without read preference
            var collection = _database.GetCollection<BsonDocument>("BalanceSnapshots");

            // VIOLATION: MONGO_NO_PROJECTION - Find without projection
            var filter = Builders<BsonDocument>.Filter.Eq("AccountId", accountId);
            var results = await collection.Find(filter)
                .Sort(Builders<BsonDocument>.Sort.Descending("SnapshotDate"))
                .ToListAsync();

            return results;
        }

        /// <summary>
        /// Searches accounts by balance range without projection or read preference.
        /// </summary>
        public async Task<List<BsonDocument>> GetAccountsByBalanceRange(
            decimal minBalance, decimal maxBalance)
        {
            // VIOLATION: MONGO_NO_READ_PREFERENCE - Collection without read preference
            var collection = _database.GetCollection<BsonDocument>("AccountBalances");

            var filterBuilder = Builders<BsonDocument>.Filter;
            var filter = filterBuilder.Gte("CurrentBalance", minBalance)
                & filterBuilder.Lte("CurrentBalance", maxBalance);

            // VIOLATION: MONGO_NO_PROJECTION - Returns all fields for every matching account
            var results = await collection.Find(filter).ToListAsync();

            return results;
        }

        /// <summary>
        /// Retrieves daily balance summaries for reporting without projection.
        /// </summary>
        public async Task<List<BsonDocument>> GetDailyBalanceSummaries(DateTime startDate, DateTime endDate)
        {
            // VIOLATION: MONGO_NO_READ_PREFERENCE - Collection without read preference
            var collection = _database.GetCollection<BsonDocument>("DailyBalanceSummaries");

            var filterBuilder = Builders<BsonDocument>.Filter;
            var filter = filterBuilder.Gte("SummaryDate", startDate)
                & filterBuilder.Lte("SummaryDate", endDate);

            // VIOLATION: MONGO_NO_PROJECTION - Returns all fields including internal audit data
            var results = await collection.Find(filter)
                .Sort(Builders<BsonDocument>.Sort.Ascending("SummaryDate"))
                .ToListAsync();

            return results;
        }

        /// <summary>
        /// Gets overdrawn accounts without projection -- exposes sensitive customer data.
        /// </summary>
        public async Task<List<BsonDocument>> GetOverdrawnAccounts()
        {
            // VIOLATION: MONGO_NO_READ_PREFERENCE - Collection without read preference
            var collection = _database.GetCollection<BsonDocument>("AccountBalances");

            var filter = Builders<BsonDocument>.Filter.Lt("CurrentBalance", 0);

            // VIOLATION: MONGO_NO_PROJECTION - Returns all fields, including PII
            var results = await collection.Find(filter)
                .Sort(Builders<BsonDocument>.Sort.Ascending("CurrentBalance"))
                .ToListAsync();

            _logger.LogWarning("Found {Count} overdrawn accounts", results.Count);
            return results;
        }

        // =====================================================================
        // CORRECT METHODS - Proper implementations for false-positive testing
        // =====================================================================

        /// <summary>
        /// Fetches account balance with proper projection and read preference.
        /// </summary>
        public async Task<AccountBalanceResult> GetAccountBalanceCorrectAsync(string accountId)
        {
            // CORRECT: Collection with explicit ReadPreference
            var readPreference = new ReadPreferenceSettings(ReadPreference.SecondaryPreferred);
            var collection = _database
                .WithReadPreference(ReadPreference.SecondaryPreferred)
                .GetCollection<BsonDocument>("AccountBalances");

            var filter = Builders<BsonDocument>.Filter.Eq("AccountId", accountId);

            // CORRECT: Explicit projection -- only return needed fields
            var projection = Builders<BsonDocument>.Projection
                .Include("AccountId")
                .Include("AccountNumber")
                .Include("CurrentBalance")
                .Include("AvailableBalance")
                .Include("LastUpdated")
                .Exclude("_id");

            var result = await collection
                .Find(filter)
                .Project(projection)
                .FirstOrDefaultAsync();

            if (result == null)
                return null;

            return new AccountBalanceResult
            {
                AccountId = result.GetValue("AccountId").AsString,
                AccountNumber = result.GetValue("AccountNumber").AsString,
                CurrentBalance = result.GetValue("CurrentBalance").ToDecimal(),
                AvailableBalance = result.GetValue("AvailableBalance").ToDecimal(),
                LastUpdated = result.GetValue("LastUpdated").ToUniversalTime()
            };
        }

        /// <summary>
        /// Retrieves balance history with projection and read preference.
        /// </summary>
        public async Task<List<BalanceSnapshot>> GetBalanceHistoryCorrectAsync(
            string accountId, int limit = 30)
        {
            // CORRECT: Database with ReadPreference configured
            var collection = _database
                .WithReadPreference(ReadPreference.SecondaryPreferred)
                .GetCollection<BsonDocument>("BalanceSnapshots");

            var filter = Builders<BsonDocument>.Filter.Eq("AccountId", accountId);

            // CORRECT: Projection limits returned fields
            var projection = Builders<BsonDocument>.Projection
                .Include("AccountId")
                .Include("SnapshotDate")
                .Include("Balance")
                .Include("AvailableBalance")
                .Exclude("_id");

            var results = await collection
                .Find(filter)
                .Project(projection)
                .Sort(Builders<BsonDocument>.Sort.Descending("SnapshotDate"))
                .Limit(limit)
                .ToListAsync();

            return results.Select(doc => new BalanceSnapshot
            {
                AccountId = doc.GetValue("AccountId").AsString,
                SnapshotDate = doc.GetValue("SnapshotDate").ToUniversalTime(),
                Balance = doc.GetValue("Balance").ToDecimal(),
                AvailableBalance = doc.GetValue("AvailableBalance").ToDecimal()
            }).ToList();
        }

        /// <summary>
        /// Searches accounts by balance range with projection and read preference.
        /// </summary>
        public async Task<List<AccountBalanceResult>> GetAccountsByBalanceRangeCorrectAsync(
            decimal minBalance, decimal maxBalance, int page = 1, int pageSize = 50)
        {
            // CORRECT: Explicit read preference for read-heavy query
            var collection = _database
                .WithReadPreference(ReadPreference.SecondaryPreferred)
                .GetCollection<BsonDocument>("AccountBalances");

            var filterBuilder = Builders<BsonDocument>.Filter;
            var filter = filterBuilder.Gte("CurrentBalance", minBalance)
                & filterBuilder.Lte("CurrentBalance", maxBalance);

            // CORRECT: Projection, pagination, and sorting
            var projection = Builders<BsonDocument>.Projection
                .Include("AccountId")
                .Include("AccountNumber")
                .Include("CurrentBalance")
                .Include("AvailableBalance")
                .Include("LastUpdated")
                .Exclude("_id");

            var results = await collection
                .Find(filter)
                .Project(projection)
                .Sort(Builders<BsonDocument>.Sort.Descending("CurrentBalance"))
                .Skip((page - 1) * pageSize)
                .Limit(pageSize)
                .ToListAsync();

            return results.Select(doc => new AccountBalanceResult
            {
                AccountId = doc.GetValue("AccountId").AsString,
                AccountNumber = doc.GetValue("AccountNumber").AsString,
                CurrentBalance = doc.GetValue("CurrentBalance").ToDecimal(),
                AvailableBalance = doc.GetValue("AvailableBalance").ToDecimal(),
                LastUpdated = doc.GetValue("LastUpdated").ToUniversalTime()
            }).ToList();
        }
    }

    // =====================================================================
    // CORRECT FACTORY - Demonstrates proper MongoClient initialization
    // =====================================================================

    /// <summary>
    /// Factory that creates a properly configured MongoClient with ReadPreference.
    /// </summary>
    public static class MongoClientFactory
    {
        public static IMongoClient CreateClient(string connectionString)
        {
            // CORRECT: MongoClientSettings with explicit ReadPreference
            var settings = MongoClientSettings.FromConnectionString(connectionString);
            settings.ReadPreference = ReadPreference.SecondaryPreferred;
            settings.ServerSelectionTimeout = TimeSpan.FromSeconds(10);
            settings.ConnectTimeout = TimeSpan.FromSeconds(10);
            settings.SocketTimeout = TimeSpan.FromSeconds(30);

            return new MongoClient(settings);
        }
    }

    // =====================================================================
    // Supporting model classes
    // =====================================================================

    public class AccountBalanceResult
    {
        public string AccountId { get; set; }
        public string AccountNumber { get; set; }
        public decimal CurrentBalance { get; set; }
        public decimal AvailableBalance { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    public class BalanceSnapshot
    {
        public string AccountId { get; set; }
        public DateTime SnapshotDate { get; set; }
        public decimal Balance { get; set; }
        public decimal AvailableBalance { get; set; }
    }
}
