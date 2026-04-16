import java.util.List;

public class LoanServicingDAO {
    public List<Object> getLoanServiceRecords(String loanId) {
        return null; // delegates to mapper
    }

    // VIOLATION: No batch executor
    public void insertLoanServiceRecords(List<Object> records) {
        for (Object record : records) {
            // individual insert
        }
    }
}
