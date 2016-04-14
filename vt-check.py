#!/usr/bin/python


import simplejson
import urllib
import urllib2
import argparse
import pprint
import json
import pprint

ap = argparse.ArgumentParser()
group = ap.add_mutually_exclusive_group(required=True)
group.add_argument('-u', nargs=1) # specify url where cipher is located,
group.add_argument('-r', nargs=2) # Retrieve report. Second arg is ated,

pp = pprint.PrettyPrinter(indent=4)


opts = ap.parse_args()
api_key = "65d2d3b5872ce5fa28eebea752486ee1aa9656dfcba0381fb6445938cff87321"

def ScheduleScan(url1):
	url = "https://www.virustotal.com/vtapi/v2/url/scan"
	parameters = {"url": "http://www.virustotal.com",
               "apikey": api_key}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json_response = response.read()
	pprint(json_response)
	#print(json.dumps(json_response, indent=2))

def RetrieveReport(url1):
	url = "https://www.virustotal.com/vtapi/v2/url/report"
	parameters = {"resource": url1,
              "apikey": api_key}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json_response = response.read()
	json_acceptable_string = json_response.replace("'", "\"")
	d = json.loads(json_acceptable_string)
	for value in d.values():
		print value
	#print type(json_response)
	#for key, value in json_response.items:
	#	print key, value

if opts.u:
	url1 = opts.u[0]
#	ScheduleScan(url1)
	RetrieveReport(url1)
