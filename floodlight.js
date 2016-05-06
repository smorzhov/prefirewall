var request = require('request');

//192.168.17.203
exports.firewallUrl = 'http://192.168.17.203:8080/wm/firewall/rules/json';
//exports.firewallUrl = 'http://localhost:8080/wm/firewall/rules/json';
exports.aclUrl = 'http://localhost:8080/wm/acl/rules/json';

exports.sendRule = function (res, url, anomaliesResolver, rule, fRule, deletedRules, tryMore, callback) {
    request({
        url: url,
        method: 'POST',
        json: true,
        body: rule
    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            if (response.body['rule-id'] != undefined) {
                //the rule has been added successfully
                fRule.setId(response.body['rule-id']);
                console.log(fRule.toString());
            } else {
                //the rule has not been added. the rule must be deleted form PreFirewall
                if (!anomaliesResolver.removeRuleByValue(fRule)) {
                    //something goes wrong. The rule wasn't added
                }
            }
            var reply =
                { status: response.body.status, 'rule-id': response.body['rule-id'], deleted: deletedRules };
            res.end(JSON.stringify(reply) + '\n');
            return;
        }
        if (tryMore) {
            setTimeout(function () {
                console.log("Waiting to repeat before sending rule again\n")
            }, 100);
            callback();
        }
        else {
            anomaliesResolver.removeRuleByValue(fRule);
            notFoundResponse(res, response, url);
        }
    })
};

exports.removeRule = function (res, url, anomaliesResolver, id, tryMore, callback) {
    request({
        url: url,
        method: 'DELETE',
        json: true,
        body: id
    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            if (response.body.status == 'Rule deleted') {
                //the rule has been deleted successfully
                var wasRemoved = anomaliesResolver.removeRuleById(id.ruleid);
            }
            res.end(JSON.stringify(response.body) + '\n');
            return;
        }
        if (tryMore) {
            setTimeout(function () {
                console.log("Waiting to repeat before removing rule again\n")
            }, 100);
            callback();
        }
        else {
            notFoundResponse(res, response, url);
        }
    })
};

exports.removeRuleFromFloodlight = function(res, url, id, tryMore, callback) {
    request({
        url: url,
        method: 'DELETE',
        json: true,
        body: id
    }, function (error, response, body) {
        var reply = '';
        if (!error && response.statusCode == 200) {
            //res.end(JSON.stringify(response.body) + '\n');
            return;
        }
        if (tryMore) {
            setTimeout(function () {
                console.log("Waiting to repeat before removing rule only from floodlight again\n")
            }, 100);
            callback();
        }
        else {
            notFoundResponse(res, response, url);
        }
    })
};

function notFoundResponse(res, floodlightRes, url) {
    if (floodlightRes == undefined) {
        res.end("Crashed");
        return;
    }
    res.end(JSON.stringify(floodlightRes.body))
}