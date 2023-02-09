import json
import requests
import base64
from configparser import ConfigParser
from sys import exit
#from charset_normalizer import md__mypyc ## Odblokowac na windowsie


config = ConfigParser()
config.read('config.ini')

api_key = config.get('Config', 'api')


def file_hash_vt(api_key):
	file_hash = input("Podaj hash pliku : ")
	url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
	headers = {
	        'X-Apikey': api_key,
	        'Accept-Encoding': 'application/json',
	      }
	try:	
		response = requests.get(url, headers=headers)
		json_resp = str(response.text)
		json_resp = json.loads(json_resp)
		
		x = json.dumps(json_resp['data']['attributes']['last_analysis_stats']['malicious'], indent=4)
		vendors = json.dumps(json_resp['data']['attributes']['last_analysis_results'])
		vendors = json.loads(vendors)
		i_x = 0

		for number in vendors:
			i_x += 1
		
		print(f'\n Plik uznawany jest za niebezpieczny przez {x}/{i_x} vendorow. \n')	

	except:
		print('Nie znaleziono hashu albo nie masz internetu \n')

	finally:
		pass	


def website_vt(api_key):
	website = input('Podaj strone do sprawdzenia : ')
	url = "https://www.virustotal.com/api/v3/urls"

	payload = f"url={website}"
	headers = {
	    "accept": "application/json",
	    "x-apikey": api_key,
	    "content-type": "application/x-www-form-urlencoded"
	}

	response = requests.post(url, data=payload, headers=headers)

	if response:
		print('Skan zaczety... poczekaj chwile i sprawdz wynik w "Sprawdz informacje na temat podejrzanej strony"')
	else:
		print('Cos poszlo nie tak... Upewnij sie czy wprowadziles poprawny URL \n')	


def website_info(api_key):
	website = input("Podaj strone : ")
	url_id = base64.urlsafe_b64encode(f"{website}".encode()).decode().strip("=")
	url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

	headers = {
	    "accept": "application/json",
	    "x-apikey": api_key
	}

	try:
		response = requests.get(url, headers=headers)
		av_engines_json = response.text
		av_engines_json = json.loads(av_engines_json)
		av_engines = json.dumps(av_engines_json['data']['attributes']['last_analysis_results'], indent=4)
		av_engines_load_json = json.loads(av_engines)

		print('\n Strona zostala uznana przez nastepujacych vendorow za zlosliwa :')
		i_vendor = 0
		for av_vendor in av_engines_load_json:
			i_vendor += 1
			vendor_info = json.dumps(av_engines_load_json[av_vendor]['category'])
			vendor_info = str(vendor_info)
			danger_list = 'malicious'
			if danger_list in vendor_info:
				print(av_vendor, ' :  ', vendor_info)
			else:
				pass
		malicious = json.dumps(av_engines_json['data']['attributes']['last_analysis_stats']['malicious'], indent=4)
		print('\n Wykrycia :')
		print('Zlosliwe : ', malicious)
		print(f'Podejrzane : ', json.dumps(av_engines_json['data']['attributes']['last_analysis_stats']['suspicious'], indent=4))
		print(f'Nieszkodliwe : ', json.dumps(av_engines_json['data']['attributes']['last_analysis_stats']['harmless'], indent=4))
		print(f'Ilosc silnikow skanujacych (vendorow) : {i_vendor}')
		print(f'\n {malicious}/{i_vendor} vendorow uwaza te strone za niebezpieczna \n')
	except:
		print('Strona mogla jeszcze nie byc skanowana, sprobuj pierw przeskanowac strone.')
	finally:
		print('\n')		

def ip_addr_vt(api_key):
	addr_ip = input("Podaj adres IP : ")
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{addr_ip}"

	headers = {
	    "accept": "application/json",
	    "x-apikey": api_key
	}

	try:	
		response = requests.get(url, headers=headers)
		av_engines_json = response.text
		av_engines_json = json.loads(av_engines_json)
		av_engines = json.dumps(av_engines_json['data']['attributes']['last_analysis_results'], indent=4)
		av_engines_load_json = json.loads(av_engines)

		print('\n Adres IP zostal uznany przez nastepujacych vendorow za zlosliwy :')
		i_vendor = 0
		for av_vendor in av_engines_load_json:
			i_vendor += 1
			vendor_info = json.dumps(av_engines_load_json[av_vendor]['category'])
			vendor_info = str(vendor_info)
			danger_list = 'malicious'
			if danger_list in vendor_info:
				print(av_vendor, ' :  ', vendor_info)
			else:
				pass


		malicious = json.dumps(av_engines_json['data']['attributes']['last_analysis_stats']['malicious'], indent=4)
		print('\n Wykrycia :')
		info = json.dumps(av_engines_json['data']['attributes']['as_owner'], indent=4)
		print('Nazwa : ', info)
		country = json.dumps(av_engines_json['data']['attributes']['country'])
		print('Kraj pochodzenia : ', country)
		print('Zlosliwe : ', malicious)
		print(f'Podejrzane : ', json.dumps(av_engines_json['data']['attributes']['last_analysis_stats']['suspicious'], indent=4))
		print(f'Nieszkodliwe : ', json.dumps(av_engines_json['data']['attributes']['last_analysis_stats']['harmless'], indent=4))
		print(f'Ilosc silnikow skanujacych (vendorow) : {i_vendor}')
		print(f'\n {malicious}/{i_vendor} vendorow uwaza ten adres IP za niebezpieczny \n')

	except:
		print('Sprawdz czy wpisales poprawny adres ip.')

	finally:
		pass


if __name__ == '__main__':

	while True:
		print('---------------------------------------------------')
		print('1. Sprawdz informacje na temat podejrzanej strony')
		print('2. Skanuj strone')
		print('3. Sprawdz informacje na temat hashu pliku')
		print('4. Sprawdz adres IP')
		print('Aby wyjsc wcisnij "q"')
		print('---------------------------------------------------')
		answer = input('Wybierz opcje : ')
		if answer == '1':
			website_info(api_key)
		elif answer == '2':
			website_vt(api_key)
		elif answer == '3':
			file_hash_vt(api_key)
		elif answer == '4':
			ip_addr_vt(api_key)	
		elif answer == 'q':
			break
			exit(0)
		else:
			print('zly wybor, aby wyjsc wcisnij "q"')		
	

