import json
import requests

api_key = ''

def file_hash_vt(api_key):

	file_hash = input("Podaj hash pliku : ")
	url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
	headers = {
	        'X-Apikey': api_key,
	        'Accept-Encoding': 'application/json',
	      }

	response = requests.get(url, headers=headers)
	json_resp = str(response.text)
	json_resp = json.loads(json_resp)
	
	x = json.dumps(json_resp['data']['attributes']['last_analysis_stats']['malicious'], indent=4)
	print(f'Plik uznawany jest za niebezpieczny przez {x} vendorow')


# def website_vt(api_key):

# 	website = input("Podaj strone do sprawdzenia : ")
# 	payload = f'url={website}'
# 	url = f"https://www.virustotal.com/api/v3/urls/"
# 	headers = {
# 	        'X-Apikey': api_key,
# 	        'Accept-Encoding': 'application/json',
# 	        'content-type': 'application/x-www-form-urlencoded'
# 	      }

# 	response = requests.post(url, data=payload, headers=headers)
# 	json_resp = str(response.text)
# 	json_resp = json.loads(json_resp)
# 	print(json_resp)
	
file_hash_vt(api_key)
#website_vt(api_key)


# print(response.text)
