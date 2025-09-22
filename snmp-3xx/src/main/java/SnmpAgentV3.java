
import com.example.Modules;
import org.snmp4j.*;
import org.snmp4j.agent.AgentConfigManager;
import org.snmp4j.agent.DefaultMOServer;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.MOServer;
import org.snmp4j.agent.io.MOInputFactory;
import org.snmp4j.agent.mo.DefaultMOFactory;
import org.snmp4j.agent.mo.MOFactory;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.agent.mo.snmp.dh.DHKickstartParameters;
import org.snmp4j.agent.mo.snmp.dh.DHKickstartParametersImpl;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.cfg.EngineBootsCounterFile;
import org.snmp4j.cfg.EngineBootsProvider;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.CounterSupport;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.transport.TransportMappings;
import org.snmp4j.util.SnmpConfigurator;
import org.snmp4j.util.ThreadPool;

import javax.crypto.Cipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

public class SnmpAgentV3 {
    static {
        SNMP4JSettings.setSecretLoggingEnabled(false);
        SNMP4JSettings.setReportSecurityLevelStrategy(SNMP4JSettings.ReportSecurityLevelStrategy.standard);
    }
    private static final LogAdapter log = LogFactory.getLogger(SnmpAgentV3.class);

    private final OctetString v2security = new OctetString("v2security");

    private AgentConfigManager agentConfigManager;
    private DefaultMOServer server;
    private Modules modules;
    private OctetString ownEngineId;

    private String address;
    private String community;
    private String context;
    private String v3user;
    private String v3AuthPassword;
    private String v3PrivPassword;

    public static final SnmpAgentV3 createSnmpAgentV3(String address, String community, String context,
                                                      String v3user, String v3AuthPassword, String v3PrivPassword) {
        SnmpAgentV3 snmpAgentV3 = new SnmpAgentV3(address, community, context, v3user, v3AuthPassword, v3PrivPassword);
        SNMP4JSettings.setExtensibilityEnabled(true);
        SecurityProtocols.getInstance().addDefaultProtocols();
        return snmpAgentV3;
    }

    private SnmpAgentV3(String address, String community, String context, String v3user, String v3AuthPassword, String v3PrivPassword) {
        this.address = address;
        this.community = community;
        this.context = context;
        this.v3user = v3user;
        this.v3AuthPassword = v3AuthPassword;
        this.v3PrivPassword = v3PrivPassword;

        try {
            log.debug("Max supported AES key length is " + Cipher.getMaxAllowedKeyLength("AES"));
        } catch (NoSuchAlgorithmException e) {
            log.error("AES privacy not supported by this VM: ", e);
        }

        server = new DefaultMOServer();
        MOServer[] moServers = new MOServer[] {server};
        List<String> listenAddress = List.of(this.address);

        MOInputFactory configurationFactory = null;
        String dhKickstartInfoPath = null;
        EngineBootsCounterFile engineBootsCounterFile = new EngineBootsCounterFile(new File("bootCounter.agent"));
        ownEngineId = engineBootsCounterFile.getEngineId(new OctetString(MPv3.createLocalEngineID()));
        setupAgent(moServers, engineBootsCounterFile, ownEngineId, listenAddress, configurationFactory, dhKickstartInfoPath);
    }

    private void setupAgent(MOServer[] moServers, EngineBootsProvider engineBootsProvider, OctetString engineID,
                            List<String> listenAddress, MOInputFactory configurationFactory, String dhKickstartInfoPath) {
        try {
            MessageDispatcher messageDispatcher = new MessageDispatcherImpl();
            addListenAddresses(messageDispatcher, listenAddress);

            Collection<DHKickstartParameters> dhKickstartParameters = Collections.emptyList();
            if (dhKickstartInfoPath != null) {
                File dhKickstartInfoFile = new File(dhKickstartInfoPath);
                if (dhKickstartInfoFile.canRead()) {
                    try {
                        try (FileInputStream fileInputStream = new FileInputStream(dhKickstartInfoFile)) {
                            Properties kickstartProperties = new Properties();
                            kickstartProperties.load(fileInputStream);
                            dhKickstartParameters = DHKickstartParametersImpl.readFromProperties("org.snmp4j.",
                                    kickstartProperties);
                        }
                    } catch (IOException e) {
                        log.error("Failed to load Diffie Hellman kickstart parameters from '" + dhKickstartInfoPath, e);
                    }
                } else {
                    log.warn("Diffie Hellman kickstart parameters file cannot be read: " + dhKickstartInfoFile);
                }
            }

            SnmpConfigurator snmpConfigurator = new SnmpConfigurator(true);

            agentConfigManager = new AgentConfigManager(engineID,
                    messageDispatcher,
                    getCustomViews(moServers),
                    moServers,
                    ThreadPool.create("SNMPAgent", 4),
                    configurationFactory,
                    null,
                    engineBootsProvider,
                    null,
                    dhKickstartParameters) {

                @Override
                protected Session createSnmpSession(MessageDispatcher dispatcher) {
                    Session sess = super.createSnmpSession(dispatcher);
                    snmpConfigurator.configure(sess, getUsm(), messageDispatcher, Collections.<String, List<Object>>emptyMap());
                    return sess;
                }
            };
            agentConfigManager.setContext(new SecurityModels(),
                    new SecurityProtocols(SecurityProtocols.SecurityProtocolSet.maxCompatibility),
                    new CounterSupport());

        } catch (Exception e) {
            log.error("Error setting up the agent", e);
        }
    }

    protected VacmMIB getCustomViews(MOServer[] moServers) {
        VacmMIB vacm = new VacmMIB(moServers);

        vacm.addGroup(SecurityModel.SECURITY_MODEL_SNMPv2c,
                v2security,
                new OctetString("v1v2group"),
                StorageType.nonVolatile);

        if (v3user != null && !v3user.isBlank()) {
            vacm.addGroup(SecurityModel.SECURITY_MODEL_USM,
                    new OctetString(v3user),
                    new OctetString("v3group"),
                    StorageType.nonVolatile);
        }

        vacm.addGroup(SecurityModel.SECURITY_MODEL_TSM,
                new OctetString(""),
                new OctetString("v3group"),
                StorageType.nonVolatile);

        vacm.addAccess(new OctetString("v1v2group"),
                new OctetString(context),
                SecurityModel.SECURITY_MODEL_ANY,
                SecurityLevel.NOAUTH_NOPRIV,
                MutableVACM.VACM_MATCH_EXACT,
                new OctetString("fullReadView"),
                new OctetString("fullWriteView"),
                new OctetString("fullNotifyView"),
                StorageType.nonVolatile);

        vacm.addAccess(new OctetString("v3group"),
                new OctetString(context),
                SecurityModel.SECURITY_MODEL_USM,
                SecurityLevel.AUTH_NOPRIV,
                MutableVACM.VACM_MATCH_EXACT,
                new OctetString("fullReadView"),
                new OctetString("fullWriteView"),
                new OctetString("fullNotifyView"),
                StorageType.nonVolatile);

        vacm.addAccess(new OctetString("v3group"),
                new OctetString(context),
                SecurityModel.SECURITY_MODEL_TSM,
                SecurityLevel.AUTH_PRIV,
                MutableVACM.VACM_MATCH_EXACT,
                new OctetString("fullReadView"),
                new OctetString("fullWriteView"),
                null,
                StorageType.nonVolatile);

        vacm.addViewTreeFamily(new OctetString("fullReadView"),
                new OID("1.3"),
                new OctetString(),
                VacmMIB.vacmViewIncluded,
                StorageType.nonVolatile);

        vacm.addViewTreeFamily(new OctetString("fullWriteView"),
                new OID("1.3"),
                new OctetString(),
                VacmMIB.vacmViewIncluded,
                StorageType.nonVolatile);

        vacm.addViewTreeFamily(new OctetString("fullNotifyView"),
                new OID("1.3"),
                new OctetString(),
                VacmMIB.vacmViewIncluded,
                StorageType.nonVolatile);

        return vacm;
    }

    protected void addListenAddresses(MessageDispatcher md, List<String> addresses) {
        for (String addressString : addresses) {
            Address addr = GenericAddress.parse(addressString);
            if (addr == null) {
                log.warn("Could not parse address string '" + addressString + "'");
                continue;
            }
            TransportMapping<? extends Address> tm = TransportMappings.getInstance().createTransportMapping(addr);
            if (tm != null) {
                md.addTransportMapping(tm);
            } else {
                log.warn("No transport mapping available for address '" + addr + "'.");
            }
        }
    }

    public void run() {
        if (agentConfigManager == null) {
            log.error("AgentConfigManager is not initialized.");
            return;
        }
        server.addContext(new OctetString(context));
        agentConfigManager.initialize();
        agentConfigManager.setupProxyForwarder();
        agentConfigManager.registerShutdownHook();
        addUsmUser();
        addV2Commutity();
        registerMIBs();
        agentConfigManager.run();
    }

    protected MOFactory getFactory() {
        return DefaultMOFactory.getInstance();
    }

    protected void addUsmUser() {
        USM usm = agentConfigManager.getUsm();
        usm.setEngineDiscoveryEnabled(true);
        if (v3user != null && !v3user.isBlank()) {
            usm.addUser(new UsmUser(
                    new OctetString(v3user),
                    AuthMD5.ID,
                    new OctetString(v3AuthPassword),
                    PrivDES.ID,
                    new OctetString(v3PrivPassword)
            ));
        }
    }

    protected void addV2Commutity() {
        if (community != null && !community.isBlank()) {
            agentConfigManager.getSnmpCommunityMIB().addSnmpCommunityEntry(
                    new OctetString("public2public"),
                    new OctetString(community),
                    v2security,
                    ownEngineId,
                    new OctetString(context),
                    new OctetString(),
                    StorageType.nonVolatile);
        }
    }

    protected void registerMIBs() {
        try {
            if (modules == null) {
                modules = new Modules();
            }
            modules.registerMOs(server, null);
        } catch (DuplicateRegistrationException e) {
            log.debug("Duplicate registration: " + e.getMessage());
        }
    }
}
