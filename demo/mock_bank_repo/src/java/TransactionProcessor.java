import java.sql.*;
import java.util.List;

public class TransactionProcessor {
    private final String oracleConnection;

    public TransactionProcessor(String connectionString) {
        this.oracleConnection = connectionString;
    }

    // VIOLATION: SELECT_STAR
    public void getTransactionHistory(String accountId) {
        try (Connection conn = DriverManager.getConnection(oracleConnection)) {
            String query = "SELECT * FROM Transactions WHERE account_id = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, accountId);
            ResultSet rs = pstmt.executeQuery();
        } catch (SQLException e) { throw new RuntimeException(e); }
    }

    // VIOLATION: SQL_INJECTION + MISSING_TIMEOUT
    public Object getTransactionById(String txnId) {
        try (Connection conn = DriverManager.getConnection(oracleConnection)) {
            // VIOLATION: SQL_INJECTION + MISSING_TIMEOUT
public Object getTransactionById(String txnId) {
    try (Connection conn = DriverManager.getConnection(oracleConnection)) {
        // CHANGED: Replaced string concatenation with a bind parameter placeholder (?) to prevent SQL injection
        String query = "SELECT * FROM Transactions WHERE transaction_id = ?";
        // CHANGED: Replaced Statement with PreparedStatement to enforce parameterized query execution
        PreparedStatement stmt = conn.prepareStatement(query);
        // CHANGED: Bind the txnId value as a parameter instead of concatenating it into the query string
        stmt.setString(1, txnId);
        ResultSet rs = stmt.executeQuery();
    } catch (SQLException e) { throw new RuntimeException(e); }
}
            public Object getTransactionById(String txnId) {
        try (Connection conn = DriverManager.getConnection(oracleConnection);
             // Use PreparedStatement instead of Statement to eliminate SQL injection via string concatenation
             PreparedStatement stmt = conn.prepareStatement("SELECT * FROM Transactions WHERE transaction_id = ?")) {
            // Bind the parameter safely; Oracle will treat it as a literal value, not executable SQL
            stmt.setString(1, txnId);
            ResultSet rs = stmt.executeQuery();
        } catch (SQLException e) { throw new RuntimeException(e); }
        return null;
    }
            ResultSet rs = stmt.executeQuery(query);
        } catch (SQLException e) { throw new RuntimeException(e); }
        return null;
    }

    // VIOLATION: UNBATCHED_UPDATES
    public void processTransactionBatch(List<String> txnIds) {
        try (Connection conn = DriverManager.getConnection(oracleConnection)) {
            for (String txnId : txnIds) {
                PreparedStatement pstmt = conn.prepareStatement(
                    "UPDATE Transactions SET status = ? WHERE transaction_id = ?");
                pstmt.setString(1, "PROCESSED");
                pstmt.setString(2, txnId);
                pstmt.executeUpdate();
            }
        } catch (SQLException e) { throw new RuntimeException(e); }
    }
}
