/**
 * Created by smorzhov on 08.04.16.
 */
exports.isValid = function (rule) {
    return isProtocolValid(rule['nw-proto']) &&
        isIpValid(rule['src-ip']) && isIpValid(rule['dst-ip']) && isPortValid(rule['tp-dst']) &&
        isActionValid(rule['action']);
};

function isProtocolValid(proto) {
    if (proto == null) return true;
    return proto == 'any' || proto == 'tcp' || proto == 'udp' || proto == 'icmp';
}

function isIpValid(ip) {
    if (ip == null) return true;
    var address = ip.split('/');
    var ipRegExp = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/i;
    return ipRegExp.test(address[0]) && address[1] != null && address[1] >= 0 && address[1] < 33;
}

function isActionValid(action) {
    return action == 'allow' || action == 'deny';
}

function isPortValid(port) {
    if (port == null) return true;
    return Number.isInteger(port) && port >= 0 && port < 0xffff;
}