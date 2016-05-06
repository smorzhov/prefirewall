import requests
import json
import re

url_fl = "http://192.168.17.203:8080/wm/firewall/rules/json"
#url_fl = "http://127.0.0.1:8080/wm/firewall/rules/json"
url_pf = "http://127.0.0.1:8090/wm/firewall/rules/json"

r_fl = requests.get(url_fl)
r_pf = requests.get(url_pf)

# json_fl = json.loads(r_fl.text)
json_fl = []
json_fl_tmp = json.loads(r_pf.text)
for elem in json_fl_tmp:
    json_fl.append(str(elem))

json_pf = json.loads(r_pf.text)

unmatched_item = set(json_fl) ^ set(json_pf)

print(unmatched_item)

print("Floodlight\tPreFirewall")
print(str(len(json_fl)) + "\t\t" + str(len(json_pf)))