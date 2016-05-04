var request = require('request');

//192.168.17.203
exports.firewallUrl = 'http://localhost:8080/wm/firewall/rules/json';
exports.aclUrl = 'http://localhost:8080/wm/acl/rules/json';

exports.sendRule = function (res, url, anomaliesResolver, rule, fRule, deletedRules) {
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
                    //something goes wrong. The rule wasn't deleted
                }
            }
            var reply = 
                {status: response.body.status, 'rule-id': response.body['rule-id'], deleted: deletedRules};
            res.end(JSON.stringify(reply) + '\n');
            return;
        }
        notFoundResponse(res, response, url);
    })
};

exports.removeRule = function (res, url, anomaliesResolver, id) {
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
        notFoundResponse(url);
        return;
    })
};

exports.removeRuleFromFloodlight = function(res, url, id) {
    //console.log(id);
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
        notFoundResponse(res, response, url);
        return;
    })
};

function notFoundResponse(res, floodlightRes, url) {
    if (floodlightRes == undefined) {
        res.end("Crashed");
        return;
    }
    res.end(JSON.stringify(floodlightRes.body))
}