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

#define LOG_TAG "OemNetd"

#include "OemNetdListener.h"
#include "InterfaceController.h"
#include "NetdConstants.h"
#include "RouteController.h"
#include "Controllers.h"
#include "ExtDataController.h"

using android::net::gCtls;
namespace com {
namespace android {
namespace internal {
namespace net {

::android::sp<::android::IBinder> OemNetdListener::getListener() {
    static OemNetdListener listener;
    return listener.getIBinder();
}

::android::sp<::android::IBinder> OemNetdListener::getIBinder() {
    std::lock_guard lock(mMutex);
    if (mIBinder == nullptr) {
        mIBinder = ::android::IInterface::asBinder(this);
    }
    return mIBinder;
}

::android::binder::Status OemNetdListener::isAlive(bool* alive) {
    ALOGD("OemNetd: isAlive return true");
    *alive = true;
    return ::android::binder::Status::ok();
}

::android::binder::Status OemNetdListener::setIpv6Mtu(const std::string& ifName, int32_t ipv6MtuValue) {
    ALOGD("setIpv6Mtu");
    std::string ipv6Mtu = std::to_string(ipv6MtuValue);

    ::android::net::InterfaceController::setIpv6Mtu(ifName.c_str(), ipv6Mtu.c_str());
    return ::android::binder::Status::ok();
}

::android::binder::Status OemNetdListener::sendExtDatacmdsToNetd(const ::std::string& cmd, int32_t* ret) {
    ALOGW("extDataCmds");
    gCtls->extdataCtl.parseExtDataCmd(cmd);
    *ret = 10;
    return ::android::binder::Status::ok();
}
/*set dns filter*/
::android::binder::Status OemNetdListener::setDnsFilterEnable(int32_t enable, int32_t* ret) {
    ALOGW("setDnsFilterEnable(%d)",enable);
    gCtls->extdataCtl.setDnsFilterEnable(enable);
    *ret = 10;
    return ::android::binder::Status::ok();
}

/* Run Iptables or ip cmds etc. */
::android::binder::Status OemNetdListener::runCmds(const std::string& cmd){
    //ALOGD("runCmds %s", cmd.c_str());
    execOemCmds(cmd);
    return ::android::binder::Status::ok();
}

::android::binder::Status OemNetdListener::registerOemUnsolicitedEventListener(
        const ::android::sp<IOemNetdUnsolicitedEventListener>& listener) {
    registerOemUnsolicitedEventListenerInternal(listener);
    listener->onRegistered();
    return ::android::binder::Status::ok();
}

void OemNetdListener::registerOemUnsolicitedEventListenerInternal(
        const ::android::sp<IOemNetdUnsolicitedEventListener>& listener) {
    std::lock_guard lock(mOemUnsolicitedMutex);

    // Create the death listener.
    class DeathRecipient : public ::android::IBinder::DeathRecipient {
      public:
        DeathRecipient(OemNetdListener* oemNetdListener,
                       ::android::sp<IOemNetdUnsolicitedEventListener> listener)
            : mOemNetdListener(oemNetdListener), mListener(std::move(listener)) {}
        ~DeathRecipient() override = default;
        void binderDied(const ::android::wp<::android::IBinder>& /* who */) override {
            mOemNetdListener->unregisterOemUnsolicitedEventListenerInternal(mListener);
        }

      private:
        OemNetdListener* mOemNetdListener;
        ::android::sp<IOemNetdUnsolicitedEventListener> mListener;
    };
    ::android::sp<::android::IBinder::DeathRecipient> deathRecipient =
            new DeathRecipient(this, listener);

    ::android::IInterface::asBinder(listener)->linkToDeath(deathRecipient);

    mOemUnsolListenerMap.insert({listener, deathRecipient});
}

void OemNetdListener::unregisterOemUnsolicitedEventListenerInternal(
        const ::android::sp<IOemNetdUnsolicitedEventListener>& listener) {
    std::lock_guard lock(mOemUnsolicitedMutex);
    mOemUnsolListenerMap.erase(listener);
}

}  // namespace net
}  // namespace internal
}  // namespace android
}  // namespace com
