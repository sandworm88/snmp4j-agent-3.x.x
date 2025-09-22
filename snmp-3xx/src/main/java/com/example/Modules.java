package com.example;

import com.example.mib.SampleMib;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.MOGroup;
import org.snmp4j.agent.MOServer;
import org.snmp4j.agent.mo.MOFactory;
import org.snmp4j.smi.OctetString;

public class Modules implements MOGroup {
    private SampleMib sampleMib;

    public Modules() {
        sampleMib = new SampleMib(123456);
    }

    public Modules(MOFactory factory) {
        sampleMib = new SampleMib(123456);
    }

    @Override
    public void registerMOs(MOServer server, OctetString context)
            throws DuplicateRegistrationException {
        sampleMib.registerMOs(server, context);
    }

    @Override
    public void unregisterMOs(MOServer server, OctetString context) {
        sampleMib.unregisterMOs(server, context);
    }

    public SampleMib getSnmp4jDemoMib() {
        return sampleMib;
    }
}
