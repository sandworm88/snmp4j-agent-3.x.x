import org.snmp4j.MessageDispatcher;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.SNMP4JSettings;
import org.snmp4j.Session;
import org.snmp4j.TransportMapping;
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
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogLevel;
import org.snmp4j.mp.CounterSupport;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.util.SnmpConfigurator;
import org.snmp4j.util.ThreadPool;

import com.example.mib.SampleMib;
import com.example.Modules;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;  
import java.util.Map;
import java.util.Properties;

import javax.crypto.Cipher;

import org.snmp4j.smi.*;
import org.snmp4j.transport.TransportMappings;  

public class MySnmpAgent {  
	
	static {
		LogFactory.setLogFactory(new ConsoleLogFactory());
		SNMP4JSettings.setSecretLoggingEnabled(true);
	}
    private static final LogAdapter logger = LogFactory.getLogger(MySnmpAgent.class);  
    protected AgentConfigManager agent;  
    private DefaultMOServer server;  
    private File configFile;  
    private File bootCounterFile; 
    protected Modules modules;
    protected Properties tableSizeLimits;
    protected OctetString context = new OctetString("context3");
    
    
    Map<String, List<Object>> securitySettings = Map.of(
    	    "oSecurityName", List.of("user"),
    	    "oAuthPassphrase", List.of("userAuthPassword"),
    	    "oPrivPassphrase", List.of("userPrivPassword"),
    	    "oAuthProtocol", List.of("MD5"),
    	    "oPrivProtocol", List.of("DES")
    	);
    
    public MySnmpAgent(String address) {  

        // Set logging level  
        LogFactory.getLogFactory().getRootLogger().setLogLevel(LogLevel.ALL);  
        SNMP4JSettings.setReportSecurityLevelStrategy(SNMP4JSettings.ReportSecurityLevelStrategy.noAuthNoPrivIfNeeded);  

        // Check max supported AES key length  
        try {  
            logger.info("Max supported AES key length is " + Cipher.getMaxAllowedKeyLength("AES"));  
        } catch (NoSuchAlgorithmException e) {  
            logger.error("AES privacy not supported by this VM: ", e);  
        } 

        // Initialize the server  
        server = new DefaultMOServer(); 
        MOServer[] moServers = new MOServer[]{server};
        List<Object> listenAddress = Arrays.asList(address);
        configFile = new File("default.config");
        bootCounterFile = new File("bootCounter.txt"); 
        
        MOInputFactory configurationFactory = null;
        String dhKickstartInfoPath = null;
        EngineBootsCounterFile engineBootsCounterFile = new EngineBootsCounterFile(bootCounterFile);
        OctetString ownEngineId = engineBootsCounterFile.getEngineId(new OctetString(MPv3.createLocalEngineID()));
        setupAgent(moServers, engineBootsCounterFile, ownEngineId, listenAddress, configurationFactory, dhKickstartInfoPath);  
    }  

    private void setupAgent(MOServer[] moServers, EngineBootsProvider engineBootsProvider, OctetString engineID, List<Object> listenAddress,  MOInputFactory configurationFactory, String dhKickstartInfoPath) {  
        try {  
        	
        	MessageDispatcher messageDispatcher = new MessageDispatcherImpl();
            addListenAddresses(messageDispatcher, listenAddress);
            
            // Uncomment to create and configure persistent provider     
            // DefaultMOPersistenceProvider persistenceProvider = new DefaultMOPersistenceProvider(new MOServer[]{server}, configFile.getAbsolutePath());  
            
            Collection<DHKickstartParameters> dhKickstartParameters = Collections.emptyList();
            if (dhKickstartInfoPath != null) {
                File dhKickstartInfoFile = new File(dhKickstartInfoPath);
                if (dhKickstartInfoFile.canRead()) {
                    try {
                        Properties kickstartProperties = new Properties();
                        FileInputStream fileInputStream = new FileInputStream(dhKickstartInfoFile);
                        kickstartProperties.load(fileInputStream);
                        fileInputStream.close();
                        dhKickstartParameters =
                                DHKickstartParametersImpl.readFromProperties("org.snmp4j.", kickstartProperties);
                    } catch (IOException iox) {
                        logger.error("Failed to load Diffie Hellman kickstart parameters from '" +
                                dhKickstartInfoPath + "': " + iox.getMessage(), iox);
                    }
                } else {
                    logger.warn("Diffie Hellman kickstart parameters file cannot be read: " + dhKickstartInfoFile);
                }
            }
            
            SnmpConfigurator snmpConfigurator = new SnmpConfigurator(true);
            
            agent = new AgentConfigManager(engineID, messageDispatcher, getCustomViews(moServers), moServers, ThreadPool.create("SampleAgent", 4), configurationFactory, null, engineBootsProvider, null, dhKickstartParameters) {
            	
                @Override
                protected Session createSnmpSession(MessageDispatcher dispatcher) {
                    Session session = super.createSnmpSession(dispatcher);
                    snmpConfigurator.configure(session, getUsm(), messageDispatcher, securitySettings);
                    return session;
                }
            };  
            System.out.println("AgentConfigManager initialized successfully.");
            agent.setContext(new SecurityModels(),
                    new SecurityProtocols(SecurityProtocols.SecurityProtocolSet.maxCompatibility), new CounterSupport()); 

        } catch (Exception e) {  
            logger.error("Error setting up the agent: ", e);  
        }  
    }  
    

    
    public VacmMIB getCustomViews(MOServer[] moServers) {
        VacmMIB vacm = new VacmMIB(moServers);
        vacm.addGroup(SecurityModel.SECURITY_MODEL_SNMPv2c, new OctetString("context3"), new OctetString("v1v2group"),
                StorageType.nonVolatile);
        vacm.addGroup(SecurityModel.SECURITY_MODEL_USM, new OctetString("user"), new OctetString("v3group"),
                StorageType.nonVolatile);
        vacm.addGroup(SecurityModel.SECURITY_MODEL_USM, new OctetString("user1"), new OctetString("v3group"),
                StorageType.nonVolatile);
        vacm.addGroup(SecurityModel.SECURITY_MODEL_USM, new OctetString("user2"), new OctetString("v3group"),
                StorageType.nonVolatile);
        vacm.addGroup(SecurityModel.SECURITY_MODEL_USM, new OctetString("user3"), new OctetString("v3group"),
                StorageType.nonVolatile);
        vacm.addGroup(SecurityModel.SECURITY_MODEL_TSM, new OctetString(""), new OctetString("v3group"),
                StorageType.nonVolatile);
        vacm.addAccess(new OctetString("v1v2group"), new OctetString("context3"), SecurityModel.SECURITY_MODEL_ANY,
                SecurityLevel.NOAUTH_NOPRIV, MutableVACM.VACM_MATCH_EXACT, new OctetString("fullReadView"),
                new OctetString("fullWriteView"), new OctetString("fullNotifyView"), StorageType.nonVolatile);

        vacm.addAccess(new OctetString("v3group"), context, SecurityModel.SECURITY_MODEL_USM,
                SecurityLevel.AUTH_NOPRIV, MutableVACM.VACM_MATCH_EXACT, new OctetString("fullReadView"),
                new OctetString("fullWriteView"), new OctetString("fullNotifyView"), StorageType.nonVolatile);
        
        vacm.addAccess(new OctetString("v3group"), context, SecurityModel.SECURITY_MODEL_TSM,
                SecurityLevel.AUTH_PRIV, MutableVACM.VACM_MATCH_EXACT, new OctetString("fullReadView"),
                new OctetString("fullWriteView"), null, StorageType.nonVolatile);

        vacm.addViewTreeFamily(new OctetString("fullReadView"), new OID("1.3"), new OctetString(),
                VacmMIB.vacmViewIncluded, StorageType.nonVolatile);
        vacm.addViewTreeFamily(new OctetString("fullWriteView"), new OID("1.3"), new OctetString(),
                VacmMIB.vacmViewIncluded, StorageType.nonVolatile);
        vacm.addViewTreeFamily(new OctetString("fullNotifyView"), new OID("1.3"), new OctetString(),
                VacmMIB.vacmViewIncluded, StorageType.nonVolatile);
        return vacm;
    }
    
    
    public void addUsmUser(USM usm) {
        logger.debug("SnmpAgentMain.addUsmUser() setEngineDiscoveryEnabled as true ");
        usm.setEngineDiscoveryEnabled(true);
        
        UsmUser user1 = new UsmUser(new OctetString("user1"), AuthMD5.ID, new OctetString("user1AuthPassword"),PrivDES.ID, new OctetString("user1PrivPassword"));
        usm.addUser(user1.getSecurityName(), usm.getLocalEngineID(), user1);
        
        UsmUser user2 = new UsmUser(new OctetString("user2"), AuthMD5.ID, new OctetString("user2AuthPassword"),PrivDES.ID, new OctetString("user2PrivPassword"));
        usm.addUser(user2.getSecurityName(), usm.getLocalEngineID(), user2);
        
        UsmUser user3 = new UsmUser(new OctetString("user3"), AuthMD5.ID, new OctetString("user3AuthPassword"),PrivDES.ID, new OctetString("user3PrivPassword"));
        usm.addUser(user3.getSecurityName(), usm.getLocalEngineID(), user3);
        
    }
    
    public void run() {  
    	if (agent == null) {
            logger.error("AgentConfigManager is not initialized.");
            return;
        }
    	server.addContext(context);
    	agent.initialize();
    	addUsmUser(agent.getUsm());
    	agent.setupProxyForwarder();
    	registerMIBs();
    	agent.registerShutdownHook();
        agent.run();  
    } 

	protected void addListenAddresses(MessageDispatcher md, List<Object> addresses) {
        for (Object addressString : addresses) {
        	System.out.println("Address being processed: " + addressString);
            Address address = GenericAddress.parse(addressString.toString());
            System.out.println("Parsed Address : " + address);
            System.out.println("Parsed address type: " + address.getClass().getName());

            if (address == null) {
                logger.fatal("Could not parse address string '" + addressString + "'");
                return;
            }
            TransportMapping<? extends Address> tm =
                    TransportMappings.getInstance().createTransportMapping(address);
            System.out.println("Transpot mapping : " + tm);
            if (tm != null) {
                md.addTransportMapping(tm);
                System.out.println("Transpot mapping successfull!" + address);
            } else {
                logger.warn("No transport mapping available for address '" +
                        address + "'.");
            }
        }         
    }
	
	protected MOFactory getFactory() {
        return DefaultMOFactory.getInstance();
    }

	
    protected void registerMIBs() {
        if (modules == null) {
            modules = new Modules(getFactory());
        }
        try {
            modules.registerMOs(server, null);
        } catch (DuplicateRegistrationException drex) {
            logger.error("Duplicate registration: " + drex.getMessage() + "." +
                    " MIB object registration may be incomplete!", drex);
        }
    }
	
    // Testing:
    // 1. snmpget -v3 -n context3 -u user1 -l authPriv -a MD5 -A user1AuthPassword -x DES -X user1PrivPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    // 2. snmpget -v3 -n context3 -u user2 -l authPriv -a MD5 -A user2AuthPassword -x DES -X user2PrivPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    // 3. snmpget -v3 -n context3 -u user3 -l authPriv -a MD5 -A user3AuthPassword -x DES -X user3PrivPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    // 4. snmpget -v3 -n context3 -u user1 -l authNoPriv -a MD5 -A user1AuthPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    // 5. snmpget -v3 -n context3 -u user2 -l authNoPriv -a MD5 -A user2AuthPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    // 6. snmpget -v3 -n context3 -u user3 -l authNoPriv -a MD5 -A user3AuthPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
	
	public static void main(String[] args) {  
		logger.info("This is a test log message.");
		MySnmpAgent sampleAgent = new MySnmpAgent("udp:127.0.0.1/4700");  
		
		// Enable extensibility if desired  
		SNMP4JSettings.setExtensibilityEnabled(true);  
		
		// Add default security protocols  
		SecurityProtocols.getInstance().addDefaultProtocols();  
		sampleAgent.run(); 
    }  
}
