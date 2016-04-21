/**
 * Created by smorzhov on 07.04.16.
 */
var http = require('http');
var url = require('url');
var static = require('node-static');

var preFirewall = require('./preFirewall');
var firewallRule = require('./firewallRule');
var aclRule = require('./aclRule');

var fileServer = new static.Server('.');

function accept(req, res) {
    var urlParsed = url.parse(req.url, true);
    switch (urlParsed.pathname) {
        case '/firewall/rules/json':
            if (req.method == 'POST') {
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
                    var fRule = preFirewall.createFloodlightFirewallRule(rule);
                    console.log(fRule.toString());
                    var conflicts = preFirewall.findAnomalies(fRule)
                    //var rules = preFirewall.getRules();
                    if (conflicts.length == 0) {
                        res.end("The rule has been successfully added!\n");
                        return;
                    }
                    var reply = "Conflicts detected! These rools were not added.s\n";
                    for (var i = 0; i < conflicts.length; i++) {
                        reply += JSON.stringify(conflicts[i]) + "\n";
                    }
                    res.end(reply);
                })
            }
            return;
        case '/acl/rules/json':
            if (req.method == 'POST') {
                req.setEncoding('utf8');
                var str = '';
                req.on('data', function (chunk) {
                    str += chunk;
                }).on ('end', function () {
                    var rule;
                    try {
                        rule = JSON.parse(str);
                    } catch (err) {
                        console.log(err);
                        res.end("Incorrect JSON!\n");
                    }
                    if (!aclRule.isValid(rule)) {
                        res.end("Incorrect rule!\n");
                    }
                    res.end(preFirewall.findAnomalies(rule));
                })
            }
            return;
        default:
            res.statusCode = 404;
            res.end("Not found");
    }
    fileServer.serve(req, res);
}

if (!module.parent) {
    http.createServer(accept).listen(8080);
    console.log("Сервер запущен на порту 8080");
} else {
    exports.accept = accept;
}