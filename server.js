/**
 * Created by smorzhov on 07.04.16.
 */
var http = require('http');
var url = require('url');
var static = require('node-static');

var preFirewall = require('./preFirewall');
var firewallRule = require('./firewallRule');
var aclRule = require('./aclRule');
var floodlight = require('./floodlight');

var fileServer = new static.Server('.');

function postRule(req, res, type) {
    req.setEncoding('utf8');
    var str = '';
    req.on('data', function (chunk) {
        str += chunk;
    }).on('end', function () {
        var rule;
        try {
            rule = JSON.parse(str);
        } catch (err) {
            console.log(err);
            res.end("Incorrect JSON!\n");
            return;
        }
        switch (type) {
            case 'firewall':
                if (!firewallRule.isValid(rule)) {
                    res.end("Incorrect rule!\n");
                    return;
                }
                break;
            case 'acl':
                if (!aclRule.isValidrule(rule)) {
                    res.end("Incorrect rule!\n");
                    return;
                }
                break;
        }
        
        var fRule;
        switch (type) {
            case 'firewall':
                fRule = preFirewall.createFirewallRule(rule);
                break;
            case 'acl':
                fRule = preFirewall.createACLRule(rule);
                break;
        }
        console.log(fRule.toString());
        var rules = preFirewall.getRules(fRule);
        var conflicts = preFirewall.findAnomalies(fRule)
        var rules = preFirewall.getRules(fRule);
        var reply = "";
        if (conflicts.length == 0) {
            switch (type) {
                case 'firewall':
                    floodlight.sendRule(res, floodlight.firewallUrl, preFirewall, fRule);
                    var rules = preFirewall.getRules(fRule);
                    return;
                case 'acl':
                    floodlight.sendRule(res, floodlight.aclUrl, preFirewall, fRule);
                    return;
            }
        }
        reply = "Conflicts detected! These rules were not added.\n";
        for (var i = 0; i < conflicts.length; i++) {
            reply += JSON.stringify(conflicts[i]) + "\n";
        }
        res.end(reply);
    })
}

function deleteRule(req, res, type) {
    req.setEncoding('utf8');
    var str = '';
    req.on('data', function (chunk) {
        str += chunk;
    }).on('end', function () {
        var id;
        try {
            id = JSON.parse(str);
        } catch (err) {
            console.log(err);
            res.end("Incorrect JSON!\n");
            return;
        }
        switch (type) {
            case 'firewall':
                floodlight.removeRule(res, floodlight.firewallUrl, preFirewall, id);
                return;
            case 'acl':
                floodlight.removeRule(res, floodlight.aclUrl, preFirewall, id);
                return;
        }
    })
}

function accept(req, res) {
    var urlParsed = url.parse(req.url, true);
    switch (urlParsed.pathname) {
        case '/firewall/rules/json':
            if (req.method == 'POST') {
                postRule(req, res, 'firewall');
            }
            if (req.method == 'DELETE') {
                deleteRule(req, res, 'firewall');
            }
            return;
        case '/acl/rules/json':
            if (req.method == 'POST') {
                postRule(req, res, 'acl');
            }
            if (req.method == 'DELETE') {
                deleteRule(req, res, 'acl');
            }
            return;
        default:
            res.statusCode = 404;
            res.end("Not found");
    }
    fileServer.serve(req, res);
}

if (!module.parent) {
    http.createServer(accept).listen(8090);
    console.log("Сервер запущен на порту 8090");
} else {
    exports.accept = accept;
}