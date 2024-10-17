# SNMP4J Agent for Version 3.6.8
SNMP4J Agent for version 3.6.8, focusing on the transition from the deprecated BaseAgent class to the AgentConfigManager class for custom agent creation. Provides guidance and examples for implementing agents using the latest API changes.

This repository contains an SNMP4J agent built using the `snmp4j-agent-3.6.8` JAR, compatible with the `snmp4j-3.7.8` manager. Compatibility is based on the official SNMP4J documentation found [here](https://snmp4j.org/agent/CHANGES.txt).

## Compatibility Information
- **Agent Version:** 3.6.8
- **Manager Version:** 3.7.8 (or later)

### Recent Changes (January 25, 2024)
- **Fixed:** `AgentConfigManager.getAgentNotificationOriginator()` now correctly returns the multi-threaded NotificationOriginator.
- **Fixed:** `SnapshotAgent.registerManagedObjects()` registers objects from snapshot files properly.
- **Improved:** `SnapshotAgent` now utilizes `AgentConfigManager` instead of the deprecated `BaseAgent`.
- **Updated:** Copyright headers for all source files.

## Running the Agent

1. Navigate to `snmp-3xx/src/main/java/MySnmpAgent.java`.
2. Run this file as a Java application in your preferred IDE. The agent will start, and logs will be displayed in the console, facilitating request monitoring.

## Testing the Agent

To test the agent, use the `snmpget` command.

1. **Download SNMPGET:**
   e.g., for Linux: `sudo apt-get install snmp`

2. **Open the terminal and run:**
   You should see output like:

   ```bash
   $ snmpget -v3 -n context3 -u user1 -l authPriv -a MD5 -A user1AuthPassword -x DES -X user1PrivPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0

   iso.3.6.1.4.1.5380.1.16.1.1.0 = INTEGER: 123456
   ```
   
   The "123456" is the value stored at the OID "1.3.6.1.4.1.5380.1.16.1.1.0" in the SampleMib.

3. **Test Cases:**
   
   - **AuthPriv Security Model:** This protocol requires both authentication and privacy (encryption). It uses MD5 for authentication, ensuring that the identity of the sender is verified, and DES (Data Encryption Standard) for encryption, securing the data being transmitted. This combination provides a high level of security for sensitive information.

   ```bash
    $ snmpget -v3 -n context3 -u user1 -l authPriv -a MD5 -A user1AuthPassword -x DES -X user1PrivPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    $ snmpget -v3 -n context3 -u user2 -l authPriv -a MD5 -A user2AuthPassword -x DES -X user2PrivPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    $ snmpget -v3 -n context3 -u user3 -l authPriv -a MD5 -A user3AuthPassword -x DES -X user3PrivPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
   ```
   - **AuthNoPriv Security Model:** This protocol requires only authentication. It uses MD5 to verify the sender's identity, but does not encrypt the data being transmitted. This is suitable for scenarios where data security is not a primary concern, but sender verification is still important.
    
   ```bash
    $ snmpget -v3 -n context3 -u user1 -l authNoPriv -a MD5 -A user1AuthPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    $ snmpget -v3 -n context3 -u user2 -l authNoPriv -a MD5 -A user2AuthPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
    $ snmpget -v3 -n context3 -u user3 -l authNoPriv -a MD5 -A user3AuthPassword 127.0.0.1:4700 1.3.6.1.4.1.5380.1.16.1.1.0
   ```
