//
// Created by smorzhov on 02.03.16.
//

#include "gtest/gtest.h"
#include "../../cpp/PreFirewallSrc/Rules/FloodlightFirewallRule.h"


class defaultAndSpecialFirewallRules : public ::testing::Test {
protected:
    FloodlightFirewallRule *defaultRule, *specialRule;

    virtual void SetUp() {
        defaultRule = new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:00", -1,
                (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:00",
                (short) FloodlightFirewallRule::DlType::ARP,
                (string &&) "0.0.0.0/0", (string &&) "0.0.0.0/0", (short) FloodlightFirewallRule::NwProto::ANY,
                0, 0, 1, (string &&) "allow"
        );
        specialRule = new FloodlightFirewallRule(
                (string &&) "00:00:00:00:00:00:00:01", 10,
                (string &&) "00:00:00:00:00:01", (string &&) "00:00:00:00:00:02",
                (short) FloodlightFirewallRule::DlType::ARP,
                (string &&) "192.168.1.10/24", (string &&) "10.10.0.0/16", (short) FloodlightFirewallRule::NwProto::ANY,
                10, 10, 2, (string &&) "deny"
        );
    }

    virtual void TearDown() {
        delete defaultRule, specialRule;
    }
};

TEST(disjointSpecialFirewallRules, isDisjointDifferentRules) {
    FloodlightFirewallRule *r = new FloodlightFirewallRule(
            (string &&) "00:00:00:00:00:00:00:00", 10,
            (string &&) "00:00:00:00:00:00", (string &&) "00:00:00:00:00:01",
            (short) FloodlightFirewallRule::DlType::IPv4,
            (string &&) "192.168.0.1/24", (string &&) "0.0.0.0/0", (short) FloodlightFirewallRule::NwProto::TCP,
            0, 10, 1, (string &&) "allow"
    );
    FloodlightFirewallRule *s = new FloodlightFirewallRule(
            (string &&) "00:00:00:00:00:00:00:01", -1,
            (string &&) "00:00:00:00:00:02", (string &&) "00:00:00:00:00:00",
            (short) FloodlightFirewallRule::DlType::IPv4,
            (string &&) "0.0.0.0/24", (string &&) "192.168.10.1/24", (short) FloodlightFirewallRule::NwProto::TCP,
            0, 20, 2, (string &&) "deny"
    );
    ASSERT_TRUE(r->isDisjoint(s));
    ASSERT_TRUE(s->isDisjoint(r));
    delete r, s;
}

TEST_F(defaultAndSpecialFirewallRules, isDisjointDifferentRules) {
    ASSERT_FALSE(defaultRule->isDisjoint(specialRule));
    ASSERT_FALSE(specialRule->isDisjoint(defaultRule));
}

TEST_F(defaultAndSpecialFirewallRules, isDisjointEqualRules) {
    ASSERT_FALSE(specialRule->isDisjoint(specialRule));
}

TEST_F(defaultAndSpecialFirewallRules, isSubsetDifferentRules) {
    ASSERT_TRUE(specialRule->isSubset(defaultRule));
    ASSERT_FALSE(defaultRule->isSubset(specialRule));
}

TEST_F(defaultAndSpecialFirewallRules, isSubsetEqualRules) {
    ASSERT_TRUE(defaultRule->isSubset(defaultRule));
}
