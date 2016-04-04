//
// Created by smorzhov on 29.02.16.
//

#include "gtest/gtest.h"
#include "../../cpp/PreFirewallSrc/Rules/FloodlightACLRule.h"


class defaultAndSpecialACLRules : public ::testing::Test {
protected:
    FloodlightACLRule *defaultRule, *specialRule;

    virtual void SetUp() {
        defaultRule = new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::ANY,
                (string &&) "0.0.0.0/0", (string &&) "0.0.0.0/0",
                0, (string &&) "allow"
        );
        specialRule = new FloodlightACLRule(
                (short) FloodlightACLRule::NwProto::TCP,
                (string &&) "192.168.1.105/24", (string &&) "10.10.0.0/16",
                10, (string &&) "deny"
        );
    }

    virtual void TearDown() {
        delete defaultRule, specialRule;
    }
};

TEST(disjointSpecialACLRules, isDisjointDifferentRules) {
    FloodlightACLRule *r = new FloodlightACLRule(
            (short) FloodlightACLRule::NwProto::ANY,
            (string &&) "192.168.10.0/24", (string &&) "0.0.0.0/0",
            10, (string &&) "allow"
    );
    FloodlightACLRule *s = new FloodlightACLRule(
            (short) FloodlightACLRule::NwProto::ICMP,
            (string &&) "192.168.10.1/24", (string &&) "10.10.10.1/27",
            15, (string &&) "deny"
    );
    ASSERT_TRUE(r->isDisjoint(s));
    ASSERT_TRUE(s->isDisjoint(r));
    delete r, s;
}


TEST_F(defaultAndSpecialACLRules, isDisjointDifferentRules) {
    ASSERT_FALSE(defaultRule->isDisjoint(specialRule));
    ASSERT_FALSE(specialRule->isDisjoint(defaultRule));
}

TEST_F(defaultAndSpecialACLRules, isDisjointEqualRules) {
    ASSERT_FALSE(specialRule->isDisjoint(specialRule));
}

TEST_F(defaultAndSpecialACLRules, isSubsetDifferentRules) {
    ASSERT_TRUE(specialRule->isSubset(defaultRule));
    ASSERT_FALSE(defaultRule->isSubset(specialRule));
}

TEST_F(defaultAndSpecialACLRules, isSubsetEqualRules) {
    ASSERT_TRUE(defaultRule->isSubset(defaultRule));
}