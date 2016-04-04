//
// Created by smorzhov on 22.02.16.
//

#pragma once

#include <stdio.h>

class IPAddress {
public:
    /**
     * Two ip addresses r and s are disjoint if r ∩ s = φ
     */
    virtual bool isDisjoint(const void *) const = 0;

    /**
     * Checks if the given ip address is a subnet address of a host address
     */
    virtual bool isSubnetAddress() const = 0;

    /**
     * An ip address r is a subset of another ip address s, or
     * r.isSubset(s) => r ⊂ s
     */
    virtual bool isSubset(void *) const = 0;

    virtual bool equals(void *) const = 0;
};
