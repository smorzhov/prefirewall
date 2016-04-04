/**
 * Created by smorzhov on 25.03.16.
 */
var http = require('http');
const preFirewall = require('./build/Release/PreFirewall.node');

var port = 8081;
var anomaliesResolver = preFirewall.createAnomaliesResolver();
var aclRule = preFirewall.createFloodlightACLRule("");
var firewallRule = preFirewall.createFloodlightFirewallRule("");

var s = http.createServer();
s.on('request', function(request, response) {
    response.writeHead(200);
    console.log(request.method);
    console.log(request.headers);
    console.log(request.url);
    var data = '';
    request.on('data', function(chunk) {
        data += chunk.toString();
    });
    request.on('end', function() {
        console.log(data);
        response.write('hi');
        response.end();
    });
});

//anomaliesResolver.findAnomalies(aclRule);

s.listen(port);
console.log('Browse to http://127.0.0.1:' + port);