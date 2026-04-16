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
    @Query("SELECT account_id, account_number, customer_id, balance, status FROM Accounts WHERE status = :status")
    public List<Object> findByStatus(@Param("status") String status) { return null; }

    // VIOLATION: SQL_INJECTION + MISSING_TIMEOUT
    @Transactional(timeout = 30)  // FIX: Batch operations - flush/commit outside the loop
    public Object findAccountByNumber(String accountNumber) {
        String query = "SELECT * FROM Accounts WHERE account_number = '" + accountNumber + "'";  // FIX: Use PreparedStatement with ? placeholders
        try (Connection conn = DriverManager.getConnection("jdbc:sqlserver://localhost:1433")) {
            Statement stmt = conn.createStatement();  // FIX: Use parameterized queries instead of string concatenation
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
