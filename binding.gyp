{
  "targets": [
    {
      "target_name": "PreFirewall",
      "sources": [
        "cpp/PreFirewallNode.cpp",
        "cpp/AnomaliesResolverWrapper/AnomaliesResolverWrapper.cpp",
        "cpp/RuleWrappers/FloodlightACLRuleWrapper.cpp",
        "cpp/RuleWrappers/FloodlightFirewallRuleWrapper.cpp",
        "cpp/PreFirewallSrc/Algorithm/AnomaliesResolver.cpp",
        "cpp/PreFirewallSrc/IPAddresses/IPv4Address.cpp",
        "cpp/PreFirewallSrc/Rules/FloodlightACLRule.cpp",
        "cpp/PreFirewallSrc/Rules/FloodlightFirewallRule.cpp"
        ],
        "cflags": ["-Wall", "-std=c++11"],
    }
  ]
}