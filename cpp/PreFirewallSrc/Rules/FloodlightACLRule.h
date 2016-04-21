//
// Created by smorzhov on 26.02.16.
//

#pragma once

#include <stdint-gcc.h>
#include <string>
#include "Rule.h"
#include "../IPAddresses/IPv4Address.h"

using namespace std;

class FloodlightACLRule : public virtual Rule {
public:
    enum class NwProto {
        ANY = 0, TCP = 6, UDP = 11, ICMP = 1
    };

    /**
     Floodlight acl rule constructor
     @Param nw-proto
     @Param src-ip
     @Param dst-ip
     @Param tpDst
     @Param action
     */
    FloodlightACLRule(short, string &&, string &&, short, string &&);

    virtual bool isSubset(void *pVoid) const override;

    virtual bool isDisjoint(void *pVoid) const override;

    virtual bool equals(void *pVoid) const override;

    virtual Action getAction() const { return this->action; }

    virtual void setAction(const Action action) { this->action = action; }

    virtual int32_t getPriority() const { return -1; }

    virtual void setPriority(int32_t) { this->priority = -1; }

    virtual int64_t getRuleId() const { return this->ruleId; }

    virtual void setRuleId(const int64_t ruleId) { this->ruleId = ruleId; }

    virtual uint32_t getOwner() const { return this->owner; }

    virtual void setOwner(const uint32_t owner) { this->owner = owner; }

    virtual string toString() const override ;

    virtual void *clone() const { return new FloodlightACLRule(*this); }

    const IPv4Address &getSrcIp() const { return srcIp; }

    const IPv4Address &getDstIp() const { return dstIp; }

    const NwProto &getNwProto() const { return nwProto; }

    short getTpDst() const { return tpDst; }

    bool isAnySrcIp() const { return anySrcIp; }

    bool isAnyDstIp() const { return anyDstIp; }

    bool isAnyTpDst() const { return anyTpDst; }

private:
    IPv4Address srcIp;
    IPv4Address dstIp;
    NwProto nwProto;
    short tpDst;

    bool anySrcIp;
    bool anyDstIp;
    bool anyTpDst;

    bool isAnyIp(string &);

    bool isAnyTp(short);

    string actionToString() const;
};