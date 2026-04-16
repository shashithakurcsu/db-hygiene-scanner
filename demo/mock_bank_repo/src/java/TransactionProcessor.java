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
            String query = "SELECT * FROM Transactions WHERE transaction_id = '" + txnId + "'";  // FIX: Use PreparedStatement with ? placeholders
            Statement stmt = conn.createStatement();  // FIX: Use parameterized queries instead of string concatenation
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
