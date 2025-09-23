
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.smi.*;

public class MOCreator {

    /**
     * Create read-only scalar object with specified OID and Value.
     *
     * @param oid   object ID
     * @param value value
     * @return managed object
     */
    public static MOScalar<Variable> createReadOnly(OID oid, Object value) {
        return new MOScalar<>(oid, MOAccessImpl.ACCESS_READ_ONLY, getVariable(value));
    }

    /**
     * Gets managed object for requested value.
     *
     * @param value value to parse
     * @return managed object
     */
    private static Variable getVariable(Object value) {
        if (value instanceof String) {
            return new OctetString((String) value);
        } else if (value instanceof Integer) {
            return new Integer32((Integer) value);
        }
        throw new IllegalArgumentException("Unmanaged Type: " + value.getClass());
    }

    /**
     * Create read/write 64bit counter field.
     *
     * @param oid  field ID
     * @param init initial value
     * @return counter field (64bit unsigned integer type)
     */
    public static MOScalar<Counter64> createCounter(String oid, Long init) {
        return new MOScalar<>(new OID(oid), MOAccessImpl.ACCESS_READ_WRITE, new Counter64(init));
    }

    /**
     * Create read/write 32bit counter field.
     *
     * @param oid  field ID
     * @param init initial value
     * @return counter field (32bit unsigned integer type)
     */
    public static MOScalar<Counter32> createCounter32(String oid, Long init) {
        return new MOScalar<>(new OID(oid), MOAccessImpl.ACCESS_READ_WRITE, new Counter32(init));
    }
}
