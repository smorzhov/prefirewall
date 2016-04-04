//
// Created by smorzhov on 29.02.16.
//

#include <gtest/gtest.h>
#include "../../cpp/PreFirewallSrc/IPAddresses/IPv4Address.h"

TEST(SubnetAddress, isSubnet) {
    IPv4Address *ip1 = new IPv4Address();
    IPv4Address *ip2 = new IPv4Address("192.168.8.0/24");
    ASSERT_TRUE(ip1->isSubnetAddress());
    ASSERT_TRUE(ip2->isSubnetAddress());
    delete ip1, ip2;
}

TEST(NotSubnetAddress, isSubnet) {
    IPv4Address *ip = new IPv4Address("10.0.10.1/27");
    ASSERT_FALSE(ip->isSubnetAddress());
    delete ip;
}

TEST(SubnetAndHost, isSubset) {
    IPv4Address *ip1 = new IPv4Address("192.168.0.0/16");
    IPv4Address *ip2 = new IPv4Address("192.168.10.1/24");
    ASSERT_TRUE(ip2->isSubset(ip1));
    ASSERT_FALSE(ip1->isSubset(ip2));
    delete ip1, ip2;
}

TEST(HostAndHost, isSubset) {
    IPv4Address *ip1 = new IPv4Address("192.168.10.10/16");
    IPv4Address *ip2 = new IPv4Address("192.168.10.1/24");
    ASSERT_TRUE(ip1->isSubset(ip1));
    ASSERT_FALSE(ip2->isSubset(ip1));
    ASSERT_FALSE(ip1->isSubset(ip2));
    delete ip1, ip2;
}

TEST(SubnetAndSubnet, isSubset) {
    IPv4Address *ip1 = new IPv4Address("192.168.0.0/16");
    IPv4Address *ip2 = new IPv4Address("192.168.10.0/24");
    ASSERT_TRUE(ip2->isSubset(ip1));
    ASSERT_FALSE(ip1->isSubset(ip2));
    delete ip1, ip2;
}

