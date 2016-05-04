import requests
import json
import re

url_floodlight = "http://127.0.0.1:8080/wm/firewall/rules/json"
url_pfw = "http://127.0.0.1:8090/wm/firewall/rules/json"

r_fl = requests.get(url_floodlight)
r_pf = requests.get(url_pfw)

formatted_text_fl = json.loads(r_fl.text)
formatted_text_pf = r_pf.text

for rule in formatted_text_fl:
    pattern = str(rule)
    matched = re.findall(pattern, formatted_text_pf)
    if len(matched) == 0:
        print(rule)
    

print(str(len(formatted_text_fl)) + ' ' + str(len(formatted_text_pf)))