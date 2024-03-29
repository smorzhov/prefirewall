/**
 * Created by smorzhov on 08.04.16.
 */
var preFirewall = require('./build/Release/PreFirewall.node')

exports.preFirewall = preFirewall;

exports.createFirewallRule = function(rule) {
    if (rule['switchid'] == undefined) rule['switchid'] = "00:00:00:00:00:00:00:00";
    if (rule['src-inport'] == undefined) rule['src-inport'] = 0;
    if (rule['src-mac'] == undefined) rule['src-mac'] = "00:00:00:00:00:00";
    if (rule['dst-mac'] == undefined) rule['dst-mac'] = "00:00:00:00:00:00";
    if (rule['src-ip'] == undefined) rule['src-ip'] = "0.0.0.0/0";
    if (rule['dst-ip'] == undefined) rule['dst-ip'] = "0.0.0.0/0";
    if (rule['tp-src'] == undefined) rule['tp-src'] = 0;
    if (rule['tp-dst'] == undefined) rule['tp-dst'] = 0;
    if (rule['priority'] == undefined) rule['priority'] = 0; 
    if (rule['dl-type'] == undefined) rule['dl-type'] = 0;
    if (rule['nw-proto'] == undefined) rule['nw-proto'] = 0;
    return preFirewall.createFloodlightFirewallRule(rule);
};

exports.createACLRule = function (rule) {
    if (rule['src-ip'] == undefined) rule['src-ip'] = "0.0.0.0/0";
    if (rule['dst-ip'] == undefined) rule['dst-ip'] = "0.0.0.0/0";
    if (rule['tp-dst'] == undefined) rule[''] = 0;
    if (rule['nw-proto'] == undefined) rule['nw-proto'] = 0;
    return preFirewall.createACLRule(rule);
};