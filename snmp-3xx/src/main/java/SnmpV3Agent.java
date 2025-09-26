
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.*;
import org.snmp4j.agent.*;
import org.snmp4j.agent.io.MOInputFactory;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.agent.mo.snmp.dh.DHKickstartParameters;
import org.snmp4j.agent.mo.snmp.dh.DHKickstartParametersImpl;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.cfg.EngineBootsCounterFile;
import org.snmp4j.cfg.EngineBootsProvider;
import org.snmp4j.mp.CounterSupport;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.TransportMappings;
import org.snmp4j.util.SnmpConfigurator;
import org.snmp4j.util.ThreadPool;

import javax.crypto.Cipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class SnmpV3Agent {

    static {
        SNMP4JSettings.setSecretLoggingEnabled(false);
        SNMP4JSettings.setReportSecurityLevelStrategy(SNMP4JSettings.ReportSecurityLevelStrategy.standard);
        SNMP4JSettings.setExtensibilityEnabled(true);
        SecurityProtocols.getInstance().addDefaultProtocols();
    }
    private static final Logger log = LoggerFactory.getLogger(SnmpV3Agent.class);

    private final OctetString v2security = new OctetString("v2security");

    private AgentConfigManager agentConfigManager;
    private DefaultMOServer server;
    private OctetString ownEngineId;

    private String address;
    private String community;
    private String context;
    private String v3user;
    private String v3AuthPassword;
    private String v3PrivPassword;

    public SnmpV3Agent(String address, String community, String context, String v3user, String v3AuthPassword, String v3PrivPassword) {
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

    public void start() {
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
        agentConfigManager.run();
    }

    public void stop() {
        agentConfigManager.shutdown();
    }

    public void registerManagedObject(ManagedObject<?> mo) {
        log.info("registerMO     [" + mo.find(mo.getScope()) + "]");
        try {
            server.register(mo, null);
        } catch (DuplicateRegistrationException ex) {
            throw new RuntimeException(ex);
        }
    }

    public void registerOID(String oid, Long initValue) throws SnmpException {
        log.info("registerOID    [" + oid + "] = " + initValue);
        if (oid == null || initValue == null) {
            throw new NullPointerException();
        }
        try {
            if (DefaultMOServer.getValue(server, null, new OID(oid)) == null) {
                MOScalar<?> mo = MOCreator.createCounter(oid, initValue);
                server.register(mo, null);
            }
        } catch (DuplicateRegistrationException ex) {
            log.error("Duplicate Managment object", ex);
            throw new SnmpException(ex);
        }
    }

    public void unregisterOID(String oid) {
        log.info("unregisterOID  [" + oid + "]");
        if (oid == null) {
            throw new NullPointerException();
        }
        server.unregister(server.getManagedObject(new OID(oid), null), null);
    }

    public boolean updateOIDvalue(String oid, Long value) {
        log.info("updateOIDvalue [" + oid + "] = " + value);
        if (oid == null || value == null) {
            throw new NullPointerException();
        }
        return DefaultMOServer.setValue(server, null, new VariableBinding(new OID(oid), new Counter64(value)));
    }

    public boolean checkOID(String oid) {
        return server.getManagedObject(new OID(oid), null) != null;
    }

    public Map<String, String> localSnmpWalk(String oidText) {
        OID rootOid = new OID(oidText);
        Map<String, String> snmpMap = new LinkedHashMap<>();
        snmpMap.put("systemMaintenance.label.snmp.oid", rootOid.toString());
        for (var iter = server.iterator(); iter.hasNext();) {
            Map.Entry<MOScope, ManagedObject<?>> nextElement = iter.next();
            if (nextElement.getValue() instanceof MOScalar<?> moScalar && moScalar.getOid().startsWith(rootOid)) {
                String value = moScalar.getValue() == null ? "null" : moScalar.getValue().toString();
                snmpMap.put(moScalar.getOid().toString(), value);
            }
        }
        return snmpMap;
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

        if (v3user != null && !v3user.isBlank()
                && v3AuthPassword != null && !v3AuthPassword.isBlank()
                && v3PrivPassword != null && !v3PrivPassword.isBlank()) {
            vacm.addGroup(SecurityModel.SECURITY_MODEL_USM,
                    new OctetString(v3user),
                    new OctetString("v3group"),
                    StorageType.nonVolatile);
        }

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

    protected void addUsmUser() {
        USM usm = agentConfigManager.getUsm();
        usm.setEngineDiscoveryEnabled(true);
        if (v3user != null && !v3user.isBlank()
                && v3AuthPassword != null && !v3AuthPassword.isBlank()
                && v3PrivPassword != null && !v3PrivPassword.isBlank()) {
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
}
