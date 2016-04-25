//
// Created by smorzhov on 18.02.16.
//

#include "FloodlightFirewallRule.h"

FloodlightFirewallRule::FloodlightFirewallRule(string&& switchId, short srcInport,
                                               string&& srcMac, string&& dstMac, short dlType,
                                               string&& srcIp, string&& dstIp, short nwProto,
                                               short tpSrc, short tpDst, uint32_t priority, string&& action) {
    this->switchId = switchId;
    anySwitchId = isAnySwitchId(switchId);
    this->srcInport = srcInport;
    anySrcInport = isAnyInport(srcInport);
    this->srcMac = srcMac;
    anySrcMac = isAnyMac(srcMac);
    this->dstMac = dstMac;
    anyDstMac = isAnyMac(dstMac);
    switch (dlType) {
        case 2048:
            this->dlType = DlType::IPv4;
            break;
        case 2054:
            this->dlType = DlType::ARP;
            break;
        default:
            this->dlType = DlType::ANY;
    }
    this->srcIp = IPv4Address(srcIp.c_str());
    anySrcIp = isAnyIp(srcIp);
    this->dstIp = IPv4Address(dstIp.c_str());
    anyDstIp = isAnyIp(dstIp);
    switch (nwProto) {
        case 1:
            this->nwProto = NwProto::UDP;
            break;
        case 6:
            this->nwProto = NwProto::TCP;
            break;
        case 17:
            this->nwProto = NwProto::ICMP;
            break;
        default:
            this->nwProto = NwProto::ANY;
    }
    this->tpSrc = tpSrc;
    anyTpSrc = isAnyTp(tpSrc);
    this->tpDst = tpDst;
    anyTpDst = isAnyTp(tpDst);
    this->priority = priority;
    transform(action.begin(), action.end(), action.begin(), ::tolower);
    if (action == "deny")
        this->action = Rule::Action::DENY;
    else this->action = Rule::Action::ALLOW;
}

bool FloodlightFirewallRule::isSubset(void* rule) const {
    FloodlightFirewallRule *s = static_cast<FloodlightFirewallRule *>(rule);
    bool isSubset = false;
    if (switchId == s->switchId || s->anySwitchId) {
        if (s->anySwitchId) isSubset = true;
    } else return false;
    if (srcInport == s->srcInport || s->anySrcInport) {
        if (s->anySrcInport) isSubset = true;
    } else return false;
    if (srcMac == s->srcMac || s->anySrcMac) {
        if (s->anySrcMac) isSubset = true;
    } else return false;
    if (dstMac == s->dstMac || s->anyDstMac) {
        if (s->anyDstMac) isSubset = true;
    } else return false;
    if (dlType == s->dlType || s->dlType == DlType::ANY) {
        if (s->dlType == DlType::ANY) isSubset = true;
    } else return false;
    if (s->anySrcIp || srcIp.isSubset(&s->srcIp) || srcIp.equals(&s->srcIp)) {
        if (s->anySrcIp || srcIp.isSubset(&s->srcIp)) isSubset = true;
    } else return false;
    if (s->anyDstIp || dstIp.isSubset(&s->dstIp) || dstIp.equals(&s->dstIp)) {
        if (s->anyDstIp || dstIp.isSubset(&s->dstIp)) isSubset = true;
    } else return false;
    if (nwProto == s->nwProto || s->nwProto == NwProto::ANY) {
        if (s->nwProto == NwProto::ANY) isSubset = true;
    } else return false;
    if (tpSrc == s->tpSrc || s->anyTpSrc) {
        if (s->anyTpSrc) isSubset = true;
    } else return false;
    if (tpDst == s->tpDst || s->anyTpDst) {
        if (s->anyTpDst) isSubset = true;
    } else return false;
    return isSubset;
}

bool FloodlightFirewallRule::isDisjoint(void* rule) const {
    FloodlightFirewallRule *s = static_cast<FloodlightFirewallRule *>(rule);
    if (switchId != s->switchId && !anySwitchId && !s->anySwitchId) return true;
    if (srcInport != s->srcInport && !anySrcInport && !s->anySrcInport) return true;
    if (srcMac != s->srcMac && !anySrcMac && !s->anySrcMac) return true;
    if (dstMac != s->dstMac && !anyDstMac && !s->anyDstMac) return true;
    if (dlType != s->dlType && dlType != DlType::ANY && s->dlType != DlType::ANY) return true;
    if (srcIp.isDisjoint(&s->srcIp) && !anySrcIp && !s->anySrcIp) return true;
    if (dstIp.isDisjoint(&s->dstIp) && !anyDstIp && !s->anyDstIp) return true;
    if (nwProto != s->nwProto && nwProto != NwProto::ANY && s->nwProto != NwProto::ANY) return true;
    if (tpSrc != s->tpSrc && !anyTpSrc && !s->anyTpSrc) return true;
    if (tpDst != s->tpDst && !anyTpDst && !s->anyTpDst) return true;
    return false;
}

bool FloodlightFirewallRule::equals(void* rule) const {
    FloodlightFirewallRule *r = static_cast<FloodlightFirewallRule *>(rule);
    return switchId == r->switchId && srcInport == r->srcInport &&
            srcMac == r->srcMac && dstMac == r->dstMac && dlType == r->dlType &&
            srcIp.equals(&r->srcIp) && dstIp.equals(&r->dstIp) && nwProto == r->nwProto &&
            tpSrc == r->tpSrc && tpDst == r->tpDst;
}

bool FloodlightFirewallRule::isAnySwitchId(string& switchId) {
    return switchId == "00:00:00:00:00:00:00:00";
}

bool FloodlightFirewallRule::isAnyInport(short inPort) {
    return inPort == -1;
}

bool FloodlightFirewallRule::isAnyMac(string& mac) {
    return mac == "00:00:00:00:00:00";
}

bool FloodlightFirewallRule::isAnyIp(string& ip) {
    return ip == "0.0.0.0/0";
}

bool FloodlightFirewallRule::isAnyTp(short tp) {
    return tp == 0;
}

string FloodlightFirewallRule::actionToString() const {
    switch (this->action) {
        case Action::ALLOW:
            return "allow";
        case Action::DENY:
            return "deny";
    }
}

std::string FloodlightFirewallRule::toString() const {
    return string("{")
            .append("\"ruleid\": \"").append(to_string(id)).append("\", ")
            .append("\"switchid\": \"").append(switchId).append("\", ")
            .append("\"src-inport\": \"").append(to_string(srcInport)).append("\", ")
            .append("\"src-mac\": \"").append(srcMac).append("\", ")
            .append("\"dst-mac\": \"").append(dstMac).append("\", ")
            .append("\"dl-type\": \"").append(to_string((int) dlType)).append("\", ")
            .append("\"src-ip\": \"").append(srcIp.getIp()).append("\", ")
            .append("\"dst-ip\": \"").append(dstIp.getIp()).append("\", ")
            .append("\"nw-proto\": \"").append(to_string((int) nwProto)).append("\", ")
            .append("\"tp-src\": \"").append(to_string(tpSrc)).append("\", ")
            .append("\"tp-dst\": \"").append(to_string(tpDst)).append("\", ")
            .append("\"priority\": \"").append(to_string(priority)).append("\", ")
            .append("\"action\": \"").append(actionToString()).append("\"")
            .append("}");
}
