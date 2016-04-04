//
// Created by smorzhov on 18.02.16.
//

#pragma once

#include<string>

class Rule {
public:
    enum class Action {
        ALLOW = 1, DENY = 0
    };

    /**
     * A rule r is a subset, or inclusively matched of another
     * rule s, denoted by <r R_IM s>, if there exists at least one criterion for which r’s
     * value is a subset of s’ value and for the rest of the attributes r’s value is equal to s’s value.
     *
     * <r R_IM s> if ∃ a⊂attr [a = φ ∧ ∀ x∈a [r.x ⊂ s.x] ∧ ∀ y∈a c [r.y = s.y]]
    */
    virtual bool isSubset(void *) const = 0;

    /**
     * Two oldRules r and s are disjoint, denoted as <r R_D s>, if they have at least
     * one criterion for which they have completely disjoint values. Formally,
     * <r R_D s> if ∃a ∈ attr[r.a ∩ s.a = φ]
     */
    virtual bool isDisjoint(void *) const = 0;

    virtual bool equals(void *) const = 0;

    virtual Action getAction() const = 0;

    virtual void setAction(const Action) = 0;

    virtual int32_t getPriority() const = 0;

    virtual void setPriority(int32_t) = 0;

    virtual uint64_t getRuleId() const = 0;

    virtual void setRuleId(const uint64_t) = 0;

    virtual uint32_t getOwner() const = 0;

    virtual void setOwner(const uint32_t) = 0;

    virtual std::string toString() const = 0;

    virtual void *clone() const = 0;

    //virtual void * split(void *) const = 0;

    virtual ~Rule() { }

protected:
    Action action;
    /**
     * lower number indicates higher priority
     */
    int32_t priority;
    uint64_t ruleId;
    uint32_t owner;
};
