import json
import os
from datetime import datetime
import time
import json

# df = pd.DataFrame([], columns=['URL','SEO','Accessibility','Performance','Best Practices'])

name = "RocketClicks" 
getdate = datetime.now().strftime("%m-%d-%y")

url = "https://semrush.com"
print('Done')


os.system('lighthouse --quiet --no-update-notifier --no-enable-error-reporting --output=json --chrome-flags="--headless" '+url)

print("Report complete for: " + url)

# f = open('report.json', encoding="utf8")
# data = json.load(f)

with open('report.json', encoding="utf8") as json_data:
        loaded_json = json.load(json_data)

seo = str(round(loaded_json["categories"]["seo"]["score"] * 100))
accessibility = str(round(loaded_json["categories"]["accessibility"]["score"] * 100))
performance = str(round(loaded_json["categories"]["performance"]["score"] * 100))
best_practices = str(round(loaded_json["categories"]["best-practices"]["score"] * 100))
audits = str(round(loaded_json["audits"]["is-on-https"]["score"] * 100))
description = str(loaded_json["audits"]["is-on-https"]["description"])

print(audits)
print(description)

print('Completed')



