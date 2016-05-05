import requests
import json
import re

url_floodlight = "http://192.168.17.203:8080/wm/firewall/rules/json"
#url_floodlight = "http://127.0.0.1:8080/wm/firewall/rules/json"
url_pfw = "http://127.0.0.1:8090/wm/firewall/rules/json"

r_fl = requests.get(url_floodlight)
r_pf = requests.get(url_pfw)

formatted_text_fl = json.loads(r_fl.text)
formatted_text_pf = json.loads(r_pf.text)


for rule in formatted_text_fl:
    if rule not in formatted_text_pf:
        print(rule)
    """matched = re.findall(pattern, formatted_text_pf)
    pattern = str(rule)
    if len(matched) == 0:
        print(rule)"""

print("Floodlight\tPreFirewall")
print(str(len(formatted_text_fl)) + "\t\t" + str(len(formatted_text_pf)))