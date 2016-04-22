//
// Created by smorzhov on 04.03.16.
//

#include "gtest/gtest.h"
#include "../../cpp/PreFirewallSrc/Algorithm/AnomaliesResolver.h"
#include "../../cpp/PreFirewallSrc/Rules/FloodlightFirewallRule.h"


class EqualFirewallRules : public ::testing::Test {
protected:
    const int numberOfRules = 3;
    vector<void *> oldRules, newRules, result;
    AnomaliesResolver *resolver;

    virtual void SetUp() {
        for (int i = 0; i < numberOfRules; i++) {
            oldRules.push_back(new FloodlightFirewallRule(
                    (string &&) "00:00:00:00:00:00:10:00", 2,
                    (string &&) "00:00:00:00:00:01", (string &&) "00:00:00:00:00:02",
                    (short) FloodlightFirewallRule::DlType::IPv4,
                    (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ANY,
                    0, 10, 1, (string &&) "allow"));
        }
        newRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:10:00", 2,
                (string &&) "00:00:00:00:00:01", (string &&) "00:00:00:00:00:02",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 10, 1, (string &&) "allow"));
        resolver = new AnomaliesResolver(oldRules);
    }

    virtual void TearDown() {
        for (int i = 0; i < oldRules.size(); ++i) {
            delete (FloodlightFirewallRule *)oldRules[i];
        }
        delete resolver, (FloodlightFirewallRule *)newRules[0];
    }
};

class RedundancyFirewallRules : public ::testing::Test {
protected:
    vector<void *> oldRules, newRules, result;
    AnomaliesResolver *resolver;

    virtual void SetUp() {
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:01", (string &&) "00:00:00:00:00:02",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 0, 1, (string &&) "deny"));
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 0, 1, (string &&) "deny"));
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:01", (string &&) "00:00:00:00:00:02",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::TCP,
                10, 10, 2, (string &&) "deny"));
        newRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 0, 1, (string &&) "deny"));
        resolver = new AnomaliesResolver(oldRules);
    }

    virtual void TearDown() {
        for (int i = 0; i < oldRules.size(); ++i) {
            delete (FloodlightFirewallRule *)oldRules[i];
        }
        delete resolver, (FloodlightFirewallRule *)newRules[0];
    }
};

class ShadowingFirewallRules : public ::testing::Test {
protected:
    vector<void *> oldRules, newRules, result;
    AnomaliesResolver *resolver;

    virtual void SetUp() {
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:01", (string &&) "00:00:00:00:00:02",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 0, 1, (string &&) "deny"));
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 0, 2, (string &&) "deny"));
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:01", (string &&) "00:00:00:00:00:02",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::TCP,
                10, 10, 1, (string &&) "allow"));
        newRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:01", (string &&) "00:00:00:00:00:02",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::TCP,
                10, 10, 1, (string &&) "allow"));
        newRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 0, 2, (string &&) "deny"));
        resolver = new AnomaliesResolver(oldRules);
    }

    virtual void TearDown() {
        for (int i = 0; i < oldRules.size(); ++i) {
            delete (FloodlightFirewallRule *)oldRules[i];
        }
        delete resolver, (FloodlightFirewallRule *)newRules[0], (FloodlightFirewallRule *)newRules[1];
    }
};

class FirewallRulesGeneralCase : public ::testing::Test {
protected:
    vector<void *> oldRules, newRules, result;
    AnomaliesResolver *resolver;

    virtual void SetUp() {
        assignOldRules();
        assignNewRules();
        resolver = new AnomaliesResolver(oldRules);
    }

    virtual void TearDown() {
        for (int i = 0; i < oldRules.size(); ++i) {
            delete (FloodlightFirewallRule *)oldRules[i];
        }
        for (int i = 0; i < newRules.size(); ++i) {
            delete (FloodlightFirewallRule *)newRules[i];
        }
        delete resolver;
    }

    void assignOldRules() {
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 0, 2, (string &&) "deny"));
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::TCP,
                10, 10, 2, (string &&) "deny"));
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:01",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::TCP,
                10, 10, 1, (string &&) "allow"));
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:01", 3,
                (string &&) "00:00:00:00:00:01", (string &&) "00:00:00:00:00:02",
                (short) FloodlightFirewallRule::DlType::ARP,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ICMP,
                20, 30, 4, (string &&) "deny"));
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:01", 3,
                (string &&) "00:00:00:00:00:01", (string &&) "00:00:00:00:00:02",
                (short) FloodlightFirewallRule::DlType::ARP,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ICMP,
                20, 30, 4, (string &&) "deny"));
        oldRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:01", 3,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::ARP,
                (string &&) "0.0.0.0/0", (string &&) "0.0.0.0/0", (short) FloodlightFirewallRule::NwProto::ICMP,
                20, 30, 3, (string &&) "deny"));
    }

    void assignNewRules() {
        newRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:01",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::TCP,
                10, 10, 1, (string &&) "allow"));
        newRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "10.10.0.0/16", (string &&) "192.168.1.0/24", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 0, 2, (string &&) "deny"));
        newRules.push_back(new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:01", 3,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::ARP,
                (string &&) "0.0.0.0/0", (string &&) "0.0.0.0/0", (short) FloodlightFirewallRule::NwProto::ICMP,
                20, 30, 3, (string &&) "deny"));
    }
};

TEST_F(EqualFirewallRules, resolveAnomalies) {
    resolver->resolveAnomalies();
    result = resolver->getNewRules();
    ASSERT_TRUE(result.size() == newRules.size());
    for (int i = 0; i < newRules.size(); ++i) {
        ASSERT_TRUE(((FloodlightFirewallRule *)result[i])->equals(newRules[i]));
    }
}

TEST_F(RedundancyFirewallRules, resolveAnomalies) {
    resolver->resolveAnomalies();
    result = resolver->getNewRules();
    ASSERT_TRUE(result.size() == newRules.size());
    for (int i = 0; i < newRules.size(); ++i) {
        ASSERT_TRUE(((FloodlightFirewallRule *)result[i])->equals(newRules[i]));
    }
}

TEST_F(ShadowingFirewallRules, resolveAnomalies) {
    resolver->resolveAnomalies();
    result = resolver->getNewRules();
    ASSERT_TRUE(result.size() == newRules.size());
    for (int i = 0; i < newRules.size(); ++i) {
        ASSERT_TRUE(((FloodlightFirewallRule *)result[i])->equals(newRules[i]));
    }
}

TEST_F(FirewallRulesGeneralCase, resolveAnomalies) {
    resolver->resolveAnomalies();
    result = resolver->getNewRules();
    ASSERT_TRUE(result.size() == newRules.size());
    for (int i = 0; i < newRules.size(); ++i) {
        ASSERT_TRUE(((FloodlightFirewallRule *)result[i])->equals(newRules[i]));
    }
}

TEST(smallTest, findAnomalies) {
    //"src-ip": "192.168.0.1/28", "dl-type": 2048, "action": "allow"
     FloodlightFirewallRule *rule = new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", 2,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::IPv4,
                (string &&) "192.168.0.1/28", (string &&) "0.0.0.0/0", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 0, 0, (string &&) "allow");
    rule->setId(1);
    AnomaliesResolver *resolver = new AnomaliesResolver();
    resolver->findAnomalies(rule);
    vector<void *> rules = resolver->getNewRules();
    ASSERT_TRUE(resolver->remove(1));
    ASSERT_TRUE(resolver->getNewRules().size() == 0);
}


TEST(DISABLED_overlapedFirewallRules, resolveAnomalies) {
    vector<void *> oldRules, newRules, result;
    oldRules.push_back(new FloodlightFirewallRule(
            (string &&) "00:00:00:00:00:00:00:00", 2,
            (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
            (short) FloodlightFirewallRule::DlType::ANY,
            (string &&) "10.0.0.1/8", (string &&) "0.0.0.0/0", (short) FloodlightFirewallRule::NwProto::ANY,
            0, 0, 2, (string &&) "allow"));
    oldRules.push_back(new FloodlightFirewallRule(
            (string &&) "00:00:00:00:00:00:00:00", 2,
            (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
            (short) FloodlightFirewallRule::DlType::ANY,
            (string &&) "0.0.0.0/0", (string &&) "0.0.0.0/0", (short) FloodlightFirewallRule::NwProto::ANY,
            80, 0, 1, (string &&) "deny"));
    AnomaliesResolver *resolver = new AnomaliesResolver(oldRules);
    resolver->resolveAnomalies();
    result = resolver->getNewRules();
    ASSERT_TRUE(1==2);
}
