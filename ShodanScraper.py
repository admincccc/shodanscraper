#!/usr/bin/env python3
# Shodan scraper
# Ignacio Lizaso

import os
from bs4 import BeautifulSoup
import requests
import urllib3
#import sys
#import re
import csv
import optparse
import urllib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL_BASE = "https://www.shodan.io/"
headers = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
"Accept-Encoding":"gzip, deflate"
}

user = ""
password = ""
pages = ""
output = ""

def login():
	# Get CSRF TOKEN
	s = requests.Session()
	r = s.get(url="https://account.shodan.io/login", allow_redirects=False, verify=False, headers=headers)
	soup = BeautifulSoup(r.content, 'html.parser')
	token = soup.find(attrs={"name": "csrf_token"})['value']

	if token is None :
		print "[-] ERROR AL OBTENER TOKEN CSRF"
		sys.exit(2)

	print "[+] Token CSRF obtenido: "+ token
	print "[ ] Realizando LogIn"

	data={
	        "username": user,
	        "password": password,
	      	"grant_type" : "password",
	      	"continue" : "https://www.shodan.io/",
	      	"csrf_token": token,
	      	"login_submit": "Log in"
	    }


	r = s.post(url="https://account.shodan.io/login", data=data, verify=False, headers=headers)

	return s


def fetch(session, query):

	with open(output, "wb") as salida:
		writer = csv.writer(salida)
		writer.writerow(["Query", query])
		writer.writerow(["IP","Hostname","added","User OS","city","Pre"])

		for x in range(0, pages):
			y = session.get(url=URL_BASE+"search?language=en&page="+str(x)+"&"+urllib.urlencode({'query': query }),
				allow_redirects=False, verify=False, headers=headers)

			soup = BeautifulSoup(y.content, 'html.parser')

			resultados = soup.findAll("div", {"class": "search-result"})

			for host in resultados:

				ip = host.findChildren(attrs={"class": "ip"})[0].get_text()

				if (len(host.findChildren(attrs={"class": "search-result-summary"})[0].findChildren("span")) == 2):
					hostname = host.findChildren(attrs={"class": "search-result-summary"})[0].findChildren("span")[0].get_text().encode('utf-8').strip()
					added = host.findChildren(attrs={"class": "search-result-summary"})[0].findChildren("span")[1].get_text().encode('utf-8').strip()

				else:
					hostname = "N/A"
					added = host.findChildren(attrs={"class": "search-result-summary"})[0].findChildren("span")[0].get_text().encode('utf-8').strip()

				os = host.findChildren(attrs={"class": "os"})[0].get_text().encode('utf-8').strip()
				city = host.findChildren(attrs={"class": "city"})[0].get_text().encode('utf-8').strip()

				pre = host.findChildren("pre")[0].get_text().encode('utf-8').strip()

				target = [ip, hostname, added, os, city, pre]

				writer.writerow(target)
			print "[+] Saving Page "+str(x)
			

def main():

	parser = optparse.OptionParser(usage='%prog [options] "query"  Example: python script.py -x 10 "port:22 country:US" ', description='Shodan query dumper. Free accounts can only access 2 pages. Example of use: ')
	parser.add_option('-u', '--user', dest='user', type='string', default="31m4i", help='Username (default: "31m4i")')
	parser.add_option('-p', '--pass', dest='password', type='string', default="q1w2e3r4", help='Password (default: "q1w2e3r4")')
	parser.add_option('-x', '--pages', dest='pages', type='int', default=2, help='Number of pages to fetch (default: "2")')
	parser.add_option('-o', '--output', dest='output', type='string', default="output.csv", help='File to save output in CSV (default: "output.csv")')


	(options, args) = parser.parse_args()
	if len(args) != 1:
		parser.error("incorrect number of arguments")
	query = args[0]
	
	global user
	global password
	global pages
	global output

	user  = options.user
	password = options.password
	pages = options.pages
	output = options.output

	fetch(login(), query)

if __name__ == "__main__":
	main()