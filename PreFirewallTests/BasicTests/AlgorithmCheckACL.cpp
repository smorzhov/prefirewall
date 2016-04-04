//
// Created by smorzhov on 13.03.16.
//
#include "gtest/gtest.h"
#include "../../cpp/PreFirewallSrc/Algorithm/AnomaliesResolver.h"
#include "../../cpp/PreFirewallSrc/Rules/FloodlightACLRule.h"


class EqualACLRules : public ::testing::Test {
protected:
    const int numberOfRules = 3;
    vector<void *> oldRules, newRules, result;
    AnomaliesResolver *resolver;

    virtual void SetUp() {
        for (int i = 0; i < numberOfRules; i++) {
            oldRules.push_back(new FloodlightACLRule(
                    (short) FloodlightACLRule::NwProto::ANY,
                    (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 0, (string &&) "deny"));
        }
        newRules.push_back(new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::ANY,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 0, (string &&) "deny"));
        resolver = new AnomaliesResolver(oldRules);
    }

    virtual void TearDown() {
        for (int i = 0; i < oldRules.size(); ++i) {
            delete (FloodlightACLRule *)oldRules[i];
        }
        delete (FloodlightACLRule *)newRules[0], resolver;
    }
};

class RedundancyACLRules : public ::testing::Test {
protected:
    vector<void *> oldRules, newRules, result;
    AnomaliesResolver *resolver;

    virtual void SetUp() {
        oldRules.push_back(new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::ICMP,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 0, (string &&) "deny"));
        oldRules.push_back(new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::UDP,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 10, (string &&) "deny"));
        oldRules.push_back(new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::ANY,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 0, (string &&) "deny"));
        newRules.push_back(new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::ANY,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 0, (string &&) "deny"));
        resolver = new AnomaliesResolver(oldRules);
    }

    virtual void TearDown() {
        for (int i = 0; i < oldRules.size(); ++i) {
            delete (FloodlightACLRule *)oldRules[i];
        }
        delete (FloodlightACLRule *)newRules[0], resolver;
    }
};

class ShadowingACLRules : public ::testing::Test {
protected:
    vector<void *> oldRules, newRules, result;
    AnomaliesResolver *resolver;

    virtual void SetUp() {
        oldRules.push_back(new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::ICMP,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 0, (string &&) "deny"));
        oldRules.push_back(new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::ANY,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 0, (string &&) "deny"));
        oldRules.push_back(new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::UDP,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 10, (string &&) "allow"));
        newRules.push_back(new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::UDP,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 10, (string &&) "allow"));
        newRules.push_back(new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::ANY,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", 0, (string &&) "deny"));
        resolver = new AnomaliesResolver(oldRules);
    }

    virtual void TearDown() {
        for (int i = 0; i < oldRules.size(); ++i) {
            delete (FloodlightACLRule *)oldRules[i];
        }
        delete (FloodlightACLRule *)newRules[0], (FloodlightACLRule *)newRules[1], resolver;
    }
};

TEST_F(EqualACLRules, resolveAnomalies) {
    resolver->resolveAnomalies();
    result = resolver->getNewRules();
    ASSERT_TRUE(result.size() == newRules.size());
    for (int i = 0; i < newRules.size(); ++i) {
        ASSERT_TRUE(((FloodlightACLRule *)result[i])->equals(newRules[i]));
    }
}

TEST_F(RedundancyACLRules, resolveAnomalies) {
    resolver->resolveAnomalies();
    result = resolver->getNewRules();
    ASSERT_TRUE(result.size() == newRules.size());
    for (int i = 0; i < newRules.size(); ++i) {
        ASSERT_TRUE(((FloodlightACLRule *)result[i])->equals(newRules[i]));
    }
}

TEST_F(ShadowingACLRules, resloveAnomalies) {
    resolver->resolveAnomalies();
    result = resolver->getNewRules();
    ASSERT_TRUE(result.size() == newRules.size());
    for (int i = 0; i < newRules.size(); ++i) {
        ASSERT_TRUE(((FloodlightACLRule *) result[i])->equals(newRules[i]));
    }
}

TEST(DISABLED_overlapedACLRules, resolveAnomalies) {
    vector<void *> oldRules, newRules, result;
    oldRules.push_back(new FloodlightACLRule(
            (short) FloodlightACLRule::NwProto::ANY,
            (string &&) "10.0.0.1/8", (string &&) "0.0.0.0/32", 0, (string &&) "allow"));
    oldRules.push_back(new FloodlightACLRule(
            (short) FloodlightACLRule::NwProto::ANY,
            (string &&) "0.0.0.0/0", (string &&) "0.0.0.0/0", 80, (string &&) "deny"));
    AnomaliesResolver *resolver = new AnomaliesResolver(oldRules);
    resolver->resolveAnomalies();
    result = resolver->getNewRules();
    ASSERT_TRUE(1==2);
}
