import json
import requests
import base64
from configparser import ConfigParser
from sys import exit
from os import path
import hashlib
from datetime import datetime
from charset_normalizer import md__mypyc 


config = ConfigParser()
config.read('config.ini')

api_key = config.get('Config', 'api')


def error_check(analysis_json):
	if json.dumps(analysis_json['error']):
		alert = True
		error_vt = json.dumps(analysis_json['error']['code'])
		print(f'Error : {error_vt}')


def analysis_check(response):
	analysis_json = response.text
	analysis_json = json.loads(analysis_json)
	error_check(analysis_json)
	analysis_get = json.dumps(analysis_json['data']['type'])
	print(f'\n {analysis_get}')


def mal_info(av_engines_json, i_vendor):	
	malicious = json.dumps(av_engines_json['data']['attributes']['last_analysis_stats']['malicious'], indent=4)
	print('\n Wykrycia :')
	print('Zlosliwe : ', malicious)
	print(f'Podejrzane : ', json.dumps(av_engines_json['data']['attributes']['last_analysis_stats']['suspicious'], indent=4))
	print(f'Nieszkodliwe : ', json.dumps(av_engines_json['data']['attributes']['last_analysis_stats']['harmless'], indent=4))
	print(f'Ilosc silnikow skanujacych (vendorow) : {i_vendor}')
	print(f'\n {malicious}/{i_vendor} vendorow uwaza te strone za niebezpieczna')


def vendor_count(response):
	json_resp = str(response.text)
	json_resp = json.loads(json_resp)
	x = json.dumps(json_resp['data']['attributes']['last_analysis_stats']['malicious'], indent=4)
	vendors = json.dumps(json_resp['data']['attributes']['last_analysis_results'])
	vendors = json.loads(vendors)
	i_x = 0

	for number in vendors:
		i_x += 1
		
	print(f'\n Plik uznawany jest za niebezpieczny przez {x}/{i_x} vendorow. \n')


def file_upload(api_key):
	file_path = input('podaj sciezke do pliku : ')
	### \x22 = ", \x27 = '
	file_path = file_path.strip('\x22\x27')
	file_size = path.getsize(file_path)
	print(f'{file_size} [B]')
		
	if file_size <= 33_554_431:
		url = "https://www.virustotal.com/api/v3/files"
		files = {"file": open(file_path, "rb")}
		#payload = {"password": password}
		headers = {
		    "accept": "application/json",
		    "x-apikey": api_key
		}

		response = requests.post(url, files=files, headers=headers)

		analysis_check(response)
		#print(response.text) 
		upload_file_hash = hash_md5(file_path)
		print(f'\n Poczekaj 2 min zanim virustotal przezeskanuje plik.\n wygenerowany hash pliku : {upload_file_hash}')
	
	elif file_size <= 681_574_399:
		url = "https://www.virustotal.com/api/v3/files/upload_url"
		headers = {
		    "accept": "application/json",
		    "x-apikey": api_key
		}

		response = requests.get(url, headers=headers)
		
		json_resp_file = str(response.text)
		json_resp_file = json.loads(json_resp_file)
		
		vt_url = json.dumps(json_resp_file['data'])
		vt_url = vt_url.strip('"')
		
		files = {"file": open(file_path, "rb")}

		response_file = requests.post(vt_url, files=files, headers=headers)
		
		analysis_json = response_file.text
		analysis_json = json.loads(analysis_json)
		analysis_get = json.dumps(analysis_json['data']['type'])
		print(f'\n {analysis_get}')

		upload_file_hash = hash_md5(file_path)
		print(f'\n Poczekaj 2 min zanim virustotal przezeskanuje plik.\n wygenerowany hash pliku : {upload_file_hash}')	

	elif file_size >= 681_574_400:
		print("Plik jest za duzy >= 650 MB")
		upload_file_hash = hash_md5(file_path)
		print(f'\n Wygenerowany hash pliku : {upload_file_hash}')
	
	else:
		print('Sprawdz czy sciezka jest poprwana')	


def mal_ven_count(response, form_ver):
	av_engines_json = response.text
	av_engines_json = json.loads(av_engines_json)
	error_check(av_engines_json)
	av_engines = json.dumps(av_engines_json['data']['attributes']['last_analysis_results'], indent=4)
	av_engines_load_json = json.loads(av_engines)

	print(f'\n Podany {form_ver} zostal uznany przez nastepujacych vendorow za zlosliwy :')
	i_vendor = 0
	for av_vendor in av_engines_load_json:
		i_vendor += 1
		vendor_info = json.dumps(av_engines_load_json[av_vendor]['category'])
		vendor_info = str(vendor_info)
		danger_list = 'malicious'
		if danger_list in vendor_info:
			print(av_vendor, ' :  ', vendor_info)
		continue

	return(av_engines_json, i_vendor)	


def file_hash_vt(api_key):
	form_ver = 'hash'
	file_hash = input("Podaj hash pliku : ")
	url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
	headers = {
	        'X-Apikey': api_key,
	        'Accept-Encoding': 'application/json',
	      }
	response = requests.get(url, headers=headers)      
	try:	
		av_engines_json, i_vendor = mal_ven_count(response, form_ver)
		mal_info(av_engines_json, i_vendor)
		file_name_vt = json.dumps(av_engines_json['data']['attributes']['meaningful_name'])
		file_name_vt = str(file_name_vt)	
		if file_name_vt:
			print(f'Nazwa pliku : {file_name_vt}')
		pass

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
		analysis_check(response)
		print('\n Skan zaczety... poczekaj chwile i sprawdz wynik w "Sprawdz informacje na temat podejrzanej strony"')
	else:	
		print('Cos poszlo nie tak... Upewnij sie czy wprowadziles poprawny URL \n')	


def website_info(api_key):
	form_ver = 'URL'
	website = input("Podaj strone : ")
	url_id = base64.urlsafe_b64encode(f"{website}".encode()).decode().strip("=")
	url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

	headers = {
	    "accept": "application/json",
	    "x-apikey": api_key
	}
	response = requests.get(url, headers=headers)
	try:	
		av_engines_json, i_vendor = mal_ven_count(response, form_ver)
		mal_info(av_engines_json, i_vendor)
		##Timestamp
		last_analysis_timestamp = json.dumps(av_engines_json['data']['attributes']['last_analysis_date'])
		if last_analysis_timestamp:
			last_analysis_timestamp = int(last_analysis_timestamp)
			last_analysis_seconds = last_analysis_timestamp / 1000
			last_analysis_date = datetime.fromtimestamp(last_analysis_timestamp)
			print(f'\n Ostatnio sprawdzane : {last_analysis_date}')	
		pass

	except:
		print('Strona mogla jeszcze nie byc skanowana, sprobuj pierw przeskanowac strone.')
	
	finally:
		print('\n')		


def ip_addr_vt(api_key):
	form_ver = 'IP'
	addr_ip = input("Podaj adres IP : ")
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{addr_ip}"

	headers = {
	    "accept": "application/json",
	    "x-apikey": api_key
	}
	response = requests.get(url, headers=headers)
	try:	
		av_engines_json, i_vendor = mal_ven_count(response, form_ver)
		mal_info(av_engines_json, i_vendor)
		
		info = json.dumps(av_engines_json['data']['attributes']['as_owner'], indent=4)
		info = str(info)
		if info:
			print('Nazwa : ', info)
		pass
			
		country = json.dumps(av_engines_json['data']['attributes']['country'])
		country = str(country)
		if country:			
			print('Kraj pochodzenia : ', country)
		pass	

	except:
		print('Sprawdz czy wpisales poprawny adres ip.')

	finally:
		pass


def hash_md5(file_path):
	BUF_SIZE = 65536   #64kB 
	md5 = hashlib.md5()
	
	with open(file_path, 'rb') as f:
	    while True:
	        data = f.read(BUF_SIZE)
	        if not data:
	            break
	        md5.update(data)

	return md5.hexdigest()        


def main():
	while True:
		print('---------------------------------------------------')
		print('1. Sprawdz informacje na temat podejrzanej strony')
		print('2. Skanuj strone')
		print('3. Sprawdz informacje na temat hashu pliku')
		print('4. Sprawdz adres IP')
		print('5. Weryfikacja pliku')
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
		elif answer == '5':
			file_upload(api_key)		
		elif answer == 'q':
			break
			exit(0)
		else:
			print('zly wybor, aby wyjsc wcisnij "q"')


if __name__ == '__main__':
	main()
