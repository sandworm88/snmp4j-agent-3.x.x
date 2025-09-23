
import org.snmp4j.agent.DuplicateRegistrationException;

public class SnmpException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Default constructor.
     *
     * @param ex parent exception.
     */
    public SnmpException(DuplicateRegistrationException ex) {
        super(ex);
    }
}
