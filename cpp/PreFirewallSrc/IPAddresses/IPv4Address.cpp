//
// Created by smorzhov on 22.02.16.
//

#include <sstream>
#include "IPv4Address.h"

IPv4Address::IPv4Address() {
    ip = "0.0.0.0/0";
    prefix = maskbits = 0;
}

IPv4Address::IPv4Address(const char *s) {
    ip = s;
    pair<uint32_t, uint8_t> pair = parseIPV4string(s);
    prefix = pair.first;
    maskbits = pair.second;
}

bool IPv4Address::isDisjoint(const void *ip) const {
    const IPv4Address *ipv4 = static_cast<const IPv4Address *>(ip);
    if (!this->isSubnetAddress() && !ipv4->isSubnetAddress())
        return !(maskbits == ipv4->maskbits && prefix == ipv4->prefix);
    if (maskbits < ipv4->maskbits && !this->isSubnetAddress())
        return true;
    if (ipv4->maskbits < maskbits && !ipv4->isSubnetAddress())
        return true;
    uint8_t mask = 0xffffffff << (32 - min(maskbits, ipv4->maskbits));
    return ((prefix & mask) != (ipv4->prefix & mask));
}

bool IPv4Address::isSubnetAddress() const {
    return (prefix & (0xffffffff << (32 - maskbits))) == prefix;
}

bool IPv4Address::isSubset(void *ip) const {
    IPv4Address *s = static_cast<IPv4Address *>(ip);
    if (!this->isSubnetAddress() && !s->isSubnetAddress())
        return maskbits == s->maskbits && prefix == s->prefix;
    if (s->maskbits > maskbits) return false;
    uint32_t mask = 0xffffffff << (32 - s->maskbits);
    return (s->isSubnetAddress() && ((prefix & mask) == (s->prefix & mask)));
}

bool IPv4Address::equals(void *ip) const {
    IPv4Address *ipv4 = static_cast<IPv4Address *>(ip);
    return prefix == ipv4->prefix && maskbits == ipv4->maskbits;
}

pair<uint32_t, uint8_t> IPv4Address::parseIPV4string(const char* ipAddress) {
    unsigned char ipbytes[4], mask;
    sscanf(ipAddress, "%hhd.%hhd.%hhd.%hhd/%hhd", &ipbytes[0], &ipbytes[1], &ipbytes[2], &ipbytes[3], &mask);
    uint32_t prefix =
            uint32_t(ipbytes[0]) << 24 |
            uint32_t(ipbytes[1]) << 16 |
            uint32_t(ipbytes[2]) << 8 |
            uint32_t(ipbytes[3]);
    return make_pair(prefix, mask % 32);
}

const string IPv4Address::getPrefix() const {
    char ipAddr[16];
    snprintf(ipAddr, sizeof ipAddr, "%u.%u.%u.%u",
             (prefix & 0xff000000) >> 24,
             (prefix & 0x00ff0000) >> 16,
             (prefix & 0x0000ff00) >> 8,
             (prefix & 0x000000ff));
    return ipAddr;
}


