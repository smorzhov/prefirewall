//
// Created by smorzhov on 18.02.16.
//

#pragma once

#include <string>
#include <algorithm>
#include "Rule.h"
#include "../IPAddresses/IPv4Address.h"

using namespace std;

class FloodlightFirewallRule : public virtual Rule {
public:
    enum class DlType {
        ANY = 0, ARP = 2054, IPv4 = 2048
    };
    enum class NwProto {
        ANY = 0, TCP = 6, UDP = 1, ICMP = 17
    };

    FloodlightFirewallRule();

    /**
     Floodlight firewall rule constructor
     @param switchId
     @param srcInport
     @param srcMac
     @param dstMac
     @param dlType
     @param srcIp
     @param dstIp
     @param nwProto
     @param tpSrc
     @param tpDst
     @param priority
     @param action
     */
    FloodlightFirewallRule(string&&, short, string&&, string&&, short, string&&,
                           string&&, short, short, short, uint32_t, string&&);

    const string &getSwitchId() const { return switchId; }

    short getSrcInport() const { return srcInport; }

    const string &getSrcMac() const { return srcMac; }

    const string &getDstMac() const { return dstMac; }

    const DlType &getDlType() const { return dlType; }

    const IPv4Address &getSrcIp() const { return srcIp; }

    const IPv4Address &getDstIp() const { return dstIp; }

    const NwProto &getNwProto() const { return nwProto; }

    short getTpSrc() const { return tpSrc; }

    short getTpDst() const { return tpDst; }

    bool isAnySwitchId() const { return anySwitchId; }

    bool isAnySrcInport() const { return anySrcInport; }

    bool isAnySrcMac() const { return anySrcMac; }

    bool isAnyDstMac() const { return anyDstMac; }

    bool isAnySrcIp() const { return anySrcIp; }

    bool isAnyDstIp() const { return anyDstIp; }

    bool isAnyTpSrc() const { return anyTpSrc; }

    bool isAnyTpDst() const { return anyTpDst; }

    virtual bool isSubset(void *) const override;

    virtual bool isDisjoint(void *) const override;

    virtual bool equals(void *) const override;

    virtual Rule::Action getAction() const { return this->action; }

    virtual void setAction(const Action action) { this->action = action; }

    virtual int32_t getPriority() const { return this->priority; }

    virtual void setPriority(int32_t priority) { this->priority = priority; }

    virtual int32_t getId() const { return this->id; }

    virtual void setId(const int32_t id) { this->id = id; }

    virtual uint32_t getOwner() const { return this->owner; }

    virtual void setOwner(const uint32_t owner) { this->owner = owner; }

    virtual std::string toString() const override;

    virtual void *clone() const { return new FloodlightFirewallRule(*this); }

private:
    string switchId;
    short srcInport;
    string srcMac;
    string dstMac;
    DlType dlType;
    IPv4Address srcIp;
    IPv4Address dstIp;
    NwProto nwProto;
    short tpSrc;
    short tpDst;
    bool anySwitchId;
    bool anySrcInport;
    bool anySrcMac;
    bool anyDstMac;
    bool anySrcIp;
    bool anyDstIp;
    bool anyTpSrc;
    bool anyTpDst;

    bool isAnySwitchId(string&);

    bool isAnyInport(short);

    bool isAnyMac(string&);

    bool isAnyIp(string&);

    bool isAnyTp(short);

    string actionToString() const;
};
