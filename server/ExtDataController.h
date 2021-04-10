
#ifndef EXTDATACONTROLLER_H_
#define EXTDATACONTROLLER_H_
#include <android-base/thread_annotations.h>
#include <android/multinetwork.h>


#include "NetdConstants.h"
#include "Permission.h"
#include "android/net/INetd.h"
#include "netdutils/DumpWriter.h"

#include <sys/types.h>
#include <list>
#include <map>
#include <set>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>

#define  CMD_TYPE_PREIFUP  0
#define  CMD_TYPE_IFUP    1
#define  CMD_TYPE_IFDOWN  2
#define  CMD_TYPE_DATAOFF_ENABLE 3
#define  CMD_TYPE_DATAOFF_DISABLE 4
#define  CMD_TYPE_END   5

#define SSLEN(str)  (sizeof(str) - 1)

#define PDP_ACTIVE_IPV4    0x0001
#define PDP_ACTIVE_IPV6    0x0002

#define ROUTE_TABLE_LAN_NETWORK    66
#define ROUTE_TABLE_WAN_NETWORK    67

#define ROUTE_TABLE_PRIORITY       9000

#define MODEM_ETH_PROP    "ro.vendor.modem.eth"

#define COMMAND_LEN 30
#define MAX_SLOT1_SETH_END  5
#define MAX_SLOT2_SETH_START  8
#define MAX_SLOT2_SETH_END  13

#define SLOT1_INDEX  0
#define SLOT2_INDEX  1
#define DEFAULT_PORT 0

#define MAX_SLOT2_SETH_END  13

struct android_net_context;

namespace android {
namespace net {


struct command {
    int cmdtype;
    char *ifname;
    unsigned int pdp_type;
    int is_autotest;
    int slotIndex;//for data off
    int sPort;
};
class ExtDataController {
public:
    ExtDataController();

    int do_preifup(struct command *c);
    void do_ifup(struct command *c);
    void do_ifdown(struct command *c);
    int process_cmd(struct command *c);
    int filterIcmpv6pkts(int ops, const char *ifname);
    int parseExtDataCmd(std::string cmd);
    void start_autotest_v4(struct command *c);
    void start_autotest_v6(struct command *c);
    void start_autotest(struct command *c);
    void stop_autotest_v4(struct command *c);
    void stop_autotest_v6(struct command *c);
    void stop_autotest(struct command *c);
    int setDnsFilterEnable(int enable);
    void do_dataOffEnable(struct command *c);
    void do_dataOffDisable(struct command *c);
    int setDataOffEnable(bool enable, int slotIndex, int port);

};
}
}
#endif
