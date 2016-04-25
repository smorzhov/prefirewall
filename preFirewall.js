/**
 * Created by smorzhov on 08.04.16.
 */
var preFirewall = require('./build/Release/PreFirewall.node')

exports.preFirewall = preFirewall;

exports.createFirewallRule = function(rule) {
    switch (rule['dl-type']) {
        case 'arp' || 'ARP':
            rule['dl-type'] = 2054;
            break;
        case 'ipv4' || 'IPV4' || 'IPv4':
            rule['dl-type'] = 2048;
            break;
        case 0 || 2048 || 2054: break;
        default:
            rule['dl-tupe'] = 0;
            break;
    }
    switch (rule['nw-proto']) {
        case 'tcp' || 'TCP':
            rule['nw-proto'] = 6;
            break;
        case 'udp' || 'UDP':
            rule['nw-proto'] = 1;
            break;
        case 'icmp' || 'ICMP':
            rule['nw-proto'] = 17;
            break;
        case 0 || 6 || 1 || 17: break;
        default:
            rule['nw-proto'] = 0;
            break;
    }
    if (rule['switchid'] == undefined) rule['switchid'] = "00:00:00:00:00:00:00:00";
    if (rule['src-inport'] == undefined) rule['src-inport'] = 0;
    if (rule['src-mac'] == undefined) rule['src-mac'] = "00:00:00:00:00:00";
    if (rule['dst-mac'] == undefined) rule['dst-mac'] = "00:00:00:00:00:00";
    if (rule['src-ip'] == undefined) rule['src-ip'] = "0.0.0.0/0";
    if (rule['dst-ip'] == undefined) rule['dst-ip'] = "0.0.0.0/0";
    if (rule['tp-src'] == undefined) rule['tp-src'] = 0;
    if (rule['tp-dst'] == undefined) rule['tp-dst'] = 0;
    if (rule['priority'] == undefined) rule['priority'] = 0; 
    return preFirewall.createFloodlightFirewallRule(rule);
};

exports.createACLRule = function (rule) {
    switch (rule['nw-proto']) {
        case 'tcp' || 'TCP':
            rule['nw-proto'] = 6;
            break;
        case 'udp' || 'UDP':
            rule['nw-proto'] = 11;
            break;
        case 'icmp' || 'ICMP':
            rule['nw-proto'] = 1;
            break;
        case 0 || 6 || 11 || 1: break;
        default:
            rule['nw-proto'] = 0;
            break;
    }
    if (rule['src-ip'] == undefined) rule['src-ip'] = "0.0.0.0/0";
    if (rule['dst-ip'] == undefined) rule['dst-ip'] = "0.0.0.0/0";
    if (rule['tp-dst'] == undefined) rule[''] = 0;
    return preFirewall.createACLRule(rule);
};