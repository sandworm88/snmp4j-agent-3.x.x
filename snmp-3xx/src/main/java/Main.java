
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;

public class Main {

    static {
        // for snmp4j debugging
        // LogFactory.setLogFactory(new ConsoleLogFactory());
        // LogFactory.getLogFactory().getRootLogger().setLogLevel(LogLevel.INFO);
    }

    // Testing:
    // 1. snmpget -v3 -n context -u user -l authPriv -a MD5 -A userAuthPassword -x DES -X userPrivPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    // 2. snmpget -v3 -n context -u user -l authNoPriv -a MD5 -A userAuthPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    // 3. snmpget -v2c -c public   127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    public static void main(String[] args) {
        SnmpV3Agent v3agent = new SnmpV3Agent("udp:0.0.0.0/4700", "public", "context", "user",
                "userAuthPassword", "userPrivPassword");
        v3agent.start();

        OID SAMPLE_OID = new OID(".1.3.6.1.4.1.5380.1.16.1.1.0");
        var sampleMib = new MOScalar<>(SAMPLE_OID, MOAccessImpl.ACCESS_READ_WRITE, new Integer32(1234567));
        v3agent.registerManagedObject(sampleMib);
    }
}
