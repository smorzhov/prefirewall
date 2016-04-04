//
// Created by smorzhov on 22.02.16.
//

#pragma once

#include <stdint-gcc.h>
#include <algorithm>
#include "IPAddress.h"

using namespace std;

class IPv4Address : public virtual IPAddress{
public:

    IPv4Address();

    IPv4Address(const char *);

    const string &getIp() const { return ip; }

    uint8_t getMaskbitsDec() const { return maskbits; }

    uint32_t getPrefixDec() const { return prefix; }

    virtual bool isDisjoint(const void*) const override;

    virtual bool isSubnetAddress() const override;

    virtual bool isSubset(void *pVoid) const override;

    virtual bool equals(void *pVoid) const override;

private:
    string ip;
    uint32_t prefix;
    uint8_t maskbits;

    pair<uint32_t, uint8_t> parseIPV4string(const char *);
};