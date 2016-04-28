/**
 * Created by smorzhov on 08.04.16.
 */
exports.isValid = function (rule) {
    return isSwithcIdValid(rule['switchid']) && isPortValid(rule['src-inport']) &&
        isMacValid(rule['src-mac']) && isMacValid(rule['dst-mac']) && isDlTypeValid(rule['dl-type']) &&
        isIpValid(rule['src-ip']) && isIpValid(rule['dst-ip']) && isProtocolValid(rule['nw-proto']) &&
        isPortValid(rule['tp-src']) && isPortValid(rule['tp-dst']) && isPriorituValid(rule['priority']) &&
        isActionValid(rule['action']);
};

function isSwithcIdValid(switchId) {
    if (switchId == null) return true;
    //todo
    return true;
}

function isPortValid(port) {
    if (port == null) return true;
    return Number.isInteger(port) && port >= 0 && port < 0xffff;
}

function isMacValid(mac) {
    if (mac == null) return true;
    var macRegExp = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/i;
    return macRegExp.test(mac);
}

function isDlTypeValid(dlType) {
    if (dlType == null) return true;
    if (dlType.isInteger()) {
        return dlType == 2048 || dlType == 2054;
    }
    if (typeof dlType === "string" || dlType instanceof String) {
        var dl = dlType.toLowerCase();
        return dl == 'arp' || dl == 'ipv4';
    }
    return false;
}

function isIpValid(ip) {
    if (ip == null) return true;
    var address = ip.split('/');
    var ipRegExp = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/i;
    return ipRegExp.test(address[0]) && address[1] != null && address[1] >= 0 && address[1] < 33;
}

function isProtocolValid(proto) {
    if (proto == null) return true;
    if (proto.isInteger()) {
        return p == 0 || p == 1 || p == 6 || p == 17;
    }
    if (typeof proto === "string" || proto instanceof String) {
        var p = proto.toLowerCase();
        return p == 'any' || p == 'tcp' || p == 'udp' || p == 'icmp';
    }
    return false;
}

function isPriorituValid(priority) {
    if (priority == null) return true;
    return Number.isInteger(priority) && priority >=0 && priority < 0xfffffff;
}

function isActionValid(action) {
    if (typeof action === "string" || action instanceof String) {
        var a = action.toLowerCase()
        return a == 'allow' || a == 'deny';
    }
    return false;
}
