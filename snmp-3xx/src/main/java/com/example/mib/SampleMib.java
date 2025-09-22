package com.example.mib;

import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.MOGroup;
import org.snmp4j.agent.MOServer;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

public class SampleMib implements MOGroup {

    public static final OID SAMPLE_OID = new OID(new int[] {1, 3, 6, 1, 4, 1, 5380, 1, 16, 1, 1, 0});
    private MOScalar<Integer32> sampleValue;

    public SampleMib(int value) {
        sampleValue = new MOScalar<>(SAMPLE_OID, MOAccessImpl.ACCESS_READ_WRITE, new Integer32(value));
        sampleValue.setVolatile(true);
    }

    @Override
    public void registerMOs(MOServer server, OctetString context) throws DuplicateRegistrationException {
        server.register(sampleValue, context);
    }

    @Override
    public void unregisterMOs(MOServer server, OctetString context) {
        server.unregister(sampleValue, context);
    }

    public Integer32 getSampleValue() {
        return sampleValue.getValue();
    }

    public void setSampleValue(Integer32 value) {
        sampleValue.setValue(value);
    }
}
