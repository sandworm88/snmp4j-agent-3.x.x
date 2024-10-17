/*_############################################################################
  _## 
  _##  SampleMIB.java  
  _## 
  _##  Copyright (C) 2024  Your Name (Your Organization)
  _##  
  _##  Licensed under the Apache License, Version 2.0 (the "License");
  _##  you may not use this file except in compliance with the License.
  _##  You may obtain a copy of the License at
  _##  
  _##      http://www.apache.org/licenses/LICENSE-2.0
  _##  
  _##  Unless required by applicable law or agreed to in writing, software
  _##  distributed under the License is distributed on an "AS IS" BASIS,
  _##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  _##  See the License for the specific language governing permissions and
  _##  limitations under the License.
  _##  
  _##########################################################################*/

package com.example.mib;

import org.snmp4j.agent.*;
import org.snmp4j.agent.mo.*;
import org.snmp4j.smi.*;

// A simple MIB implementation
public class SampleMib implements MOGroup {

    // Object identifier for the scalar object
    public static final OID SAMPLE_OID = new OID(new int[]{1, 3, 6, 1, 4, 1, 5380, 1, 16, 1, 1, 0});

    // A scalar object for storing an integer value
    private MOScalar<Integer32> sampleValue;

    public SampleMib(int value) {
        // Create a new scalar object with read-write access
        sampleValue = new MOScalar<>(SAMPLE_OID, MOAccessImpl.ACCESS_READ_WRITE, new Integer32(value));
        sampleValue.setVolatile(true);
    }

    public void registerMOs(MOServer server, OctetString context) throws DuplicateRegistrationException {
        server.register(sampleValue, context);
    }

    public void unregisterMOs(MOServer server, OctetString context) {
        server.unregister(sampleValue, context);
    }

    // Getter for the sample value
    public Integer32 getSampleValue() {
        return sampleValue.getValue();
    }

    // Setter for the sample value
    public void setSampleValue(Integer32 value) {
        sampleValue.setValue(value);
    }
}
