
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogLevel;

public class Main {

    static {
        LogFactory.setLogFactory(new ConsoleLogFactory());
        LogFactory.getLogFactory().getRootLogger().setLogLevel(LogLevel.ALL);
    }

    // Testing:
    // 1. snmpget -v3 -n context3 -u user -l authPriv -a MD5 -A userAuthPassword -x DES -X userPrivPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    // 2. snmpget -v3 -n context3 -u user -l authNoPriv -a MD5 -A userAuthPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    // 3. snmpget -v2c -c public   127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    public static void main(String[] args) {
        SnmpAgentV3 v3agent = SnmpAgentV3.createSnmpAgentV3("udp:0.0.0.0/4700", "public", "user",
                "userAuthPassword", "userPrivPassword");
        v3agent.run();
    }
}
