/**
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.net;

import com.android.internal.net.IOemNetdUnsolicitedEventListener;

/** {@hide} */
interface IOemNetd {
   /**
    * Returns true if the service is responding.
    */
    boolean isAlive();

   /**
    * Register oem unsolicited event listener
    *
    * @param listener oem unsolicited event listener to register
    */
    void registerOemUnsolicitedEventListener(IOemNetdUnsolicitedEventListener listener);

   /**
    * set mtu for ipv6
    */
    void setIpv6Mtu(in @utf8InCpp String ifName, int mtu);

    /**
    * Run Iptables or ip cmds etc.
    */
    void runCmds(in @utf8InCpp String cmd);

    /**
    * send extData cmd to netd
    */
    int sendExtDatacmdsToNetd(in @utf8InCpp String cmd);

    /**
     * set dns filter
     */
    int setDnsFilterEnable(int enable);
}
