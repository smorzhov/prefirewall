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

var firewallAnomaliesResolver = preFirewall.preFirewall.createAnomaliesResolver();
var aclAnomaliesResolver = preFirewall.preFirewall.createAnomaliesResolver();
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
            console.log(err + ". JSON.parse(str) crashed!\n");
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

        var fRule, conflicts;
        switch (type) {
            case 'firewall':
                fRule = preFirewall.createFirewallRule(rule);
                conflicts = firewallAnomaliesResolver.findAnomalies(fRule);
                break;
            case 'acl':
                fRule = preFirewall.createACLRule(rule);
                conflicts = aclAnomaliesResolver.findAnomalies(fRule);
                break;
        }
        var reply = {status: "", 'rule-id': ""};
        var mustBeAdded = false;
        var deletedRules = 0;
        for (var i = 0; i < conflicts.length; i++) {
            if (conflicts[i].type == 0) {
                reply['status'] = "Conflicts detected! The rule was not added.";
                reply['rule-id'] = JSON.stringify(conflicts[i]) + "\n";
            } else {
                var id = {"ruleid": conflicts[i]['rule-id']};
                switch (type) {
                    case 'firewall':
                        console.log(id);
                        floodlight.removeRuleFromFloodlight(res, floodlight.firewallUrl, id, true,
                            function () {
                                floodlight.removeRuleFromFloodlight(res, floodlight.firewallUrl, id, false);
                            });
                        mustBeAdded = true;
                        deletedRules++;
                        break;
                    case 'acl':
                        floodlight.removeRuleFromFloodlight(res, floodlight.aclUrl, id, true, function () {
                            floodlight.removeRuleFromFloodlight(res, floodlight.aclUrl, id,false);
                        });
                        mustBeAdded = true;
                        deletedRules++;
                        break;
                }
            }
        }
        if (conflicts.length == 0 || mustBeAdded) {
            switch (type) {
                case 'firewall':
                    floodlight.sendRule(res, floodlight.firewallUrl, firewallAnomaliesResolver, rule, 
                        fRule, deletedRules, true, function () {
                            floodlight.sendRule(res, floodlight.firewallUrl, firewallAnomaliesResolver, rule, 
                                fRule, deletedRules, false)
                        });
                    return;
                case 'acl':
                    floodlight.sendRule(floodlight.aclUrl, aclAnomaliesResolver, rule, fRule, deletedRules, 
                        true, function () {
                            floodlight.sendRule(floodlight.aclUrl, aclAnomaliesResolver, rule, fRule, deletedRules, false);
                        });
                    return;
            }
        }
        res.end(JSON.stringify(reply));
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
                floodlight.removeRule(res, floodlight.firewallUrl, firewallAnomaliesResolver, id, true,
                    function () {
                        floodlight.removeRule(res, floodlight.firewallUrl, firewallAnomaliesResolver, id, false);                        
                    });
                return;
            case 'acl':
                floodlight.removeRule(res, floodlight.aclUrl, aclAnomaliesResolver, id, true,
                    function () {
                        floodlight.removeRule(res, floodlight.aclUrl, aclAnomaliesResolver, id, false);
                    });
                return;
        }
    })
}

function getRules(res, type) {
    var rules;
    switch (type) {
        case 'firewall':
            rules = firewallAnomaliesResolver.getRules();
            break;
        case 'acl':
            rules = aclAnomaliesResolver.getRules();
            break;
    }
    if (rules.length == 0) {
        res.end("No rules\n");
        return;
    }
    res.end(JSON.stringify(rules));
    /*var reply = "";
    for (var i = 0; i < rules.length; i++) {
        reply += rules[i].toString() + '\n';
    }
    res.end(reply);*/
}

function accept(req, res) {
    var urlParsed = url.parse(req.url, true);
    switch (urlParsed.pathname) {
        case '/wm/firewall/rules/json':
            if (req.method == 'POST') {
                postRule(req, res, 'firewall');
            }
            if (req.method == 'DELETE') {
                deleteRule(req, res, 'firewall');
            }
            if (req.method == 'GET') {
                getRules(res, 'firewall');
            }
            break;
        case '/wm/acl/rules/json':
            if (req.method == 'POST') {
                postRule(req, res, 'acl');
            }
            if (req.method == 'DELETE') {
                deleteRule(req, res, 'acl');
            }
            if (req.method == 'GET') {
                getRules(res, 'acl');
            }
            break;
        default:
            res.statusCode = 404;
            res.end("Not found");
            fileServer.serve(req, res);
    }
}

if (!module.parent) {
    http.createServer(accept).listen(8090);
    console.log("Сервер запущен на порту 8090");
} else {
    exports.accept = accept;
}