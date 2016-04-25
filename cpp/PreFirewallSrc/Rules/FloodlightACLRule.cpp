//
// Created by smorzhov on 26.02.16.
//

#include "FloodlightACLRule.h"

FloodlightACLRule::FloodlightACLRule(short nwProto, string&& srcIp, string&& dstIp, short tpDst, string&& action) {
    switch (nwProto) {
        case 1:
            this->nwProto = NwProto::ICMP;
            break;
        case 6:
            this->nwProto = NwProto::TCP;
            break;
        case 11:
            this->nwProto = NwProto::UDP;
            break;
        default:
            this->nwProto = NwProto::ANY;
    }
    this->srcIp = IPv4Address(srcIp.c_str());
    anySrcIp = isAnyIp(srcIp);
    this->dstIp = IPv4Address(dstIp.c_str());
    anyDstIp = isAnyIp(dstIp);
    this->tpDst = tpDst;
    anyTpDst = isAnyTp(tpDst);
    transform(action.begin(), action.end(), action.begin(), ::tolower);
    if (action == "deny")
        this->action = Action::DENY;
    else this->action = Action::ALLOW;
}

bool FloodlightACLRule::isSubset(void *rule) const {
    FloodlightACLRule *s = static_cast<FloodlightACLRule *>(rule);
    bool isSubset = false;
    if (nwProto == s->nwProto || s->nwProto == NwProto::ANY) {
        if (s->nwProto == NwProto::ANY) isSubset = true;
    } else return false;
    if (s->anySrcIp || srcIp.isSubset(&s->srcIp) || srcIp.equals(&s->srcIp)) {
        if (s->anySrcIp || srcIp.isSubset(&s->srcIp)) isSubset = true;
    } else return false;
    if (s->anyDstIp || dstIp.isSubset(&s->dstIp) || dstIp.equals(&s->dstIp)) {
        if (s->anyDstIp || dstIp.isSubset(&s->dstIp)) isSubset = true;
    } else return false;
    if (tpDst == s->tpDst || s->anyTpDst) {
        if (s->anyTpDst) isSubset = true;
    } else return false;
    return isSubset;
}

bool FloodlightACLRule::isDisjoint(void *rule) const {
    FloodlightACLRule *s = static_cast<FloodlightACLRule *>(rule);
    if (nwProto != s->nwProto && nwProto != NwProto::ANY && s->nwProto != NwProto::ANY) return true;
    if (srcIp.isDisjoint(&s->srcIp) && !anySrcIp && !s->anySrcIp) return true;
    if (dstIp.isDisjoint(&s->dstIp) && !anyDstIp && !s->anyDstIp) return true;
    if (tpDst != s->tpDst && !anyTpDst && !s->anyTpDst) return true;
    return false;
}

bool FloodlightACLRule::equals(void *rule) const {
    FloodlightACLRule *fRule = static_cast<FloodlightACLRule *>(rule);
    return nwProto == fRule->nwProto && srcIp.equals(&fRule->srcIp) && dstIp.equals(&fRule->dstIp) &&
            tpDst == fRule->tpDst;
}

bool FloodlightACLRule::isAnyIp(string& ip) {
    return ip == "0.0.0.0/0";
}

bool FloodlightACLRule::isAnyTp(short tp) {
    return tp == 0;
}

string FloodlightACLRule::actionToString() const {
    switch (this->action) {
        case Action::ALLOW:
            return "allow";
        case Action::DENY:
            return "deny";
    }
}

string FloodlightACLRule::toString() const {
    return string("{")
            .append("\"ruleid\": \"").append(to_string(id)).append("\", ")
            .append("\"nw-proto\": \"").append(to_string((int) nwProto)).append("\", ")
            .append("\"src-ip\": \"").append(srcIp.getIp()).append("\", ")
            .append("\"dst-ip\": \"").append(dstIp.getIp()).append("\", ")
            .append("\"tp-dst\": \"").append(to_string(tpDst)).append("\", ")
            .append("\"action\": \"").append(actionToString()).append("\"")
            .append("}");
}

