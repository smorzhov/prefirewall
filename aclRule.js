/**
 * Created by smorzhov on 08.04.16.
 */
exports.validate = function (rule) {
    return 
};

function isProtocolValid(proto) {
    if (proto == null) return true;
    return proto.toLowerCase() == 'tcp' || proto == 0 ||
        proto == 'udp'.toLowerCase() || proto == 1 ||
        proto == 'icmp'.toLowerCase() || proto == 17;
}

function isIpValid(ip) {
    if (ip == null) return true;
    var address = ip.split('/');
    var ipRegExp = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/i;
    return ipRegExp.test(address[0]) && address[1] != null && address[1] >= 0 && address[1] < 33;
}

function isActionValid(action) {
    return action.toLowerCase() == 'allow' || action.toLowerCase() == 'deny';
}

function isPortValid(port) {
    if (port == null) return true;
    return Number.isInteger(port) && port >= 0 && port < 0xff;
}