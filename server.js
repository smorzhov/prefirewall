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

function postFirewallRule(req, res) {
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
        if (!firewallRule.isValid(rule)) {
            res.end("Incorrect rule!\n");
            return;
        }
        var fRule = preFirewall.createFirewallRule(rule);
        console.log(fRule.toString());
        var conflicts = preFirewall.findAnomalies(fRule)
        //var rules = preFirewall.getRules();
        var reply = "";
        if (conflicts.length == 0) {
            floodlight.postFirewallRule(res, floodlight.firewallUrl, rule);
            return;
        }
        reply = "Conflicts detected! These rules were not added.\n";
        for (var i = 0; i < conflicts.length; i++) {
            reply += JSON.stringify(conflicts[i]) + "\n";
        }
        res.end(reply);
    })
}

function postACLRule(req, res) {
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
        if (!aclRule.isValid(rule)) {
            res.end("Incorrect rule!\n");
            return;
        }
        var aclRule = preFirewall.createACLRule(rule);
        console.log(aclRule.toString());
        var conflicts = preFirewall.findAnomalies(aclRule)
        //var rules = preFirewall.getRules();
        var reply = "";
        if (conflicts.length == 0) {
            reply = "The rule has been added successfully!\n";

            res.end(reply);
            return;
        }
        reply = "Conflicts detected! These rules were not added.\n";
        for (var i = 0; i < conflicts.length; i++) {
            reply += JSON.stringify(conflicts[i]) + "\n";
        }
        res.end(reply);
    })
}

function accept(req, res) {
    var urlParsed = url.parse(req.url, true);
    switch (urlParsed.pathname) {
        case '/firewall/rules/json':
            if (req.method == 'POST') {
                postFirewallRule(req, res);
            }
            return;
        case '/acl/rules/json':
            if (req.method == 'POST') {
                postACLRule(req, res);
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