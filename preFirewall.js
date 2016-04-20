/**
 * Created by smorzhov on 08.04.16.
 */
var preFirewall = require('./build/Debug/PreFirewall.node')
var anomaliesResolver = preFirewall.createAnomaliesResolver();

exports.findAnomalies = function(rule) {
    return anomaliesResolver.findAnomalies(rule);
};

exports.createFloodlightFirewallRule = function(rule) {
    return preFirewall.createFloodlightFirewallRule(rule);
};

exports.undoChanges = function() {
    anomaliesResolver.undoChanges();
};

exports.getRules = function() {
    return anomaliesResolver.getRules();
};