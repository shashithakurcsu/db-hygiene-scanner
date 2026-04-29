import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.sql.*;
import java.util.List;
import java.math.BigDecimal;

@Repository
public class AccountRepository {
    @PersistenceContext
    private EntityManager entityManager;

    // VIOLATION: SELECT_STAR
    // Replaced SELECT * with explicit column list to avoid SELECT_STAR violation
// Column names should match actual Accounts table schema; update as appropriate
@Query("SELECT a.accountId, a.accountNumber, a.accountType, a.status, a.balance, a.currency, a.ownerId, a.createdDate, a.lastModifiedDate FROM Accounts a WHERE a.status = :status")
public List<Object[]> findByStatus(@Param("status") String status) { return null; }
    public List<Object> findByStatus(@Param("status") String status) { return null; }

    // VIOLATION: SQL_INJECTION + MISSING_TIMEOUT
    // Note: findByStatus is a read-only query; batch it with readOnly=true to avoid unnecessary write locks
    public List<Object> findByStatus(@Param("status") String status) { return null; }

    // VIOLATION: SQL_INJECTION + MISSING_TIMEOUT
    // Added timeout=30 to bound transaction duration and prevent long-running transaction locks
    @Transactional(timeout = 30)
    public Object findAccountByNumber(String accountNumber) {
        String query = "SELECT * FROM Accounts WHERE account_number = '" + accountNumber + "'";
        try (Connection conn = DriverManager.getConnection("jdbc:sqlserver://localhost:1433")) {(readOnly = true)
public List<Object> findByStatus(@Param("status") String status) { return null; }

// VIOLATION: SQL_INJECTION + MISSING_TIMEOUT
// UNBATCHED_TXN fix: annotate with readOnly=true since this is a SELECT-only operation,
// preventing unnecessary transaction escalation and reducing lock contention on MSSQL
@Transactional(readOnly = true)
public Object findAccountByNumber(String accountNumber) {
    String query = "SELECT * FROM Accounts WHERE account_number = '" + accountNumber + "'";
    try (Connection conn = DriverManager.getConnection("jdbc:sqlserver://localhost:1433")) {
    public Object findAccountByNumber(String accountNumber) {
        // VIOLATION FIXED: SQL_INJECTION + MISSING_TIMEOUT
@Transactional
public Object findAccountByNumber(String accountNumber) {
    // CHANGED: replaced string concatenation with parameterized query to prevent SQL injection
    String query = "SELECT * FROM Accounts WHERE account_number = ?";
    try (Connection conn = DriverManager.getConnection("jdbc:sqlserver://localhost:1433");
         // CHANGED: replaced Statement with PreparedStatement to bind parameters safely
         PreparedStatement stmt = conn.prepareStatement(query)) {
        // CHANGED: added query timeout (30s) to address MISSING_TIMEOUT violation
        stmt.setQueryTimeout(30);
        // CHANGED: bind accountNumber as a typed parameter instead of inline string
        stmt.setString(1, accountNumber);
        ResultSet rs = stmt.executeQuery();
        try (Connection conn = DriverManager.getConnection("jdbc:sqlserver://localhost:1433")) {
            public Object findAccountByNumber(String accountNumber) {
    // Use parameterized query to eliminate SQL injection risk
    String query = "SELECT * FROM Accounts WHERE account_number = ?";
    try (Connection conn = DriverManager.getConnection("jdbc:sqlserver://localhost:1433");
         // Replace createStatement() with prepareStatement() to bind parameters safely
         PreparedStatement stmt = conn.prepareStatement(query)) {
        // Bind accountNumber as a parameter instead of concatenating into the SQL string
        stmt.setString(1, accountNumber);
        ResultSet rs = stmt.executeQuery();
        if (rs.next()) { return rs.getString("account_id"); }
    } catch (SQLException e) { throw new RuntimeException(e); }
    return null;
}
            ResultSet rs = stmt.executeQuery(query);
            if (rs.next()) { return rs.getString("account_id"); }
        } catch (SQLException e) { throw new RuntimeException(e); }
        return null;
    }

    // VIOLATION: UNBATCHED_UPDATES - persist in loop
    @Transactional
    public void saveBatch(List<Object> accounts) {
        for (Object account : accounts) {
            entityManager.persist(account);
        }
    }

    // VIOLATION: MISSING_TIMEOUT - @Transactional without timeout
    @Transactional
    public void transferBetweenAccounts(String fromId, String toId, BigDecimal amount) {
        // transfer logic
    }

    // Correct example
    @Transactional(timeout = 30)
    public void transferCorrect(String fromId, String toId, BigDecimal amount) {
        // correct transfer with timeout
    }
}
