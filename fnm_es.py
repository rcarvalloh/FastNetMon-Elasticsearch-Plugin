#!/usr/bin/python3

#
#Important!!! You need to make sure you're pointing to your python exec...
#

import requests, sys, datetime, json, re
from elasticsearch import Elasticsearch
import fnm_dictionary, config

#Regex for the traffic sample matcher
trf_sample_regex = re.compile(r"^((-*\d{2,4}){3}) ((:*\d{2}){3}.\d+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+) > (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+) protocol: ([a-z]+) frag: (\d+)  packets: (\d+) size: (\d+) bytes ttl: (\d+) sample ratio: (\d+)$")

#FastNetMon arguments 

fnm_client_ip = sys.argv[1]
fnm_attack_direction = sys.argv[2]
fnm_power_pps = sys.argv[3]
fnm_action = sys.argv[4]
fnm_attack_details = "".join(sys.stdin.readlines()) 

##################################################   
#Functions that the App uses
##################################################
def process_fnm_main(report):
   reportDict = {}
   for entry in report:
      key, value = entry.split(':')
      value_filtered = value.replace(' packets per second', '').replace(' flows per second', '').replace(' ','')
      value_unit = value_filtered.find('bps')
      if value_unit != -1: 
         value_unit = value_filtered[ value_unit - 1 ]
         value_filtered = int(value_filtered.replace(value_unit+'bps', '')) * fnm_dictionary.CONV_TABLE[value_unit]
	  
      translated_key = fnm_dictionary.main_attribute[key]
      reportDict[translated_key] = is_value_int(value_filtered)
   return reportDict
	  
def process_fnm_traffic(report):
   pass 

def update_es_index():
   #FNM details processing
   #FNM returns the data divided in sections each section has a line in between
   #This is just so processing each section is easier 
   fnm_attack_det_sections = fnm_attack_details.split('\n\n')
   main_attack_det = fnm_attack_det_sections[0]
   if config.FNM_NETWORK_ACCOUNTING == True and len(fnm_attack_det_sections) == 3:
      network_attack_det = fnm_attack_det_sections[1]
      traffic_sample = fnm_attack_det_sections[2]
   else:
      traffic_sample = fnm_attack_det_sections[1]

   #we get a dictionary with main report attributes	  
   main_info = process_fnm_main(main_attack_det.split('\n'))

   es_conn = Elasticsearch([{'host': config.ES_SERVER_IP, 'port': config.ES_SERVER_PORT}])
   #getting the time in UTC
   timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
   main_info['timestamp'] = timestamp
   
   #sending data to ES
   response = es_conn.index(index=config.ES_INDEX, doc_type=config.ES_DOCTYPE, body=main_info)

def notify_via_slack():
   if config.DETAILS_TO_SLACK == False and fnm_action == 'attack_details': return
   
   if fnm_action == 'ban':
      slack_color = "danger"
   elif fnm_action == 'attack_details':
      slack_color = "warning"
   elif fnm_action == 'unban':
      slack_color = "good"
   else:
      return 
   
   slack_text = "IP: '{0}'\nAttack: '{1}'\nPPS: '{2}'\nAction: '{3}'\n\n'{4}'".format(fnm_client_ip, fnm_attack_direction, fnm_power_pps, fnm_action, fnm_attack_details)
   slack_payload = json.dumps({'attachments': [ { 'title': config.SLACK_TITLE, 'text': slack_text, 'color': slack_color } ] })
   
   
   #Actual slack connection
   response = requests.post(config.SLACK_URL, data=slack_payload, headers={'Content-Type': 'application/json'})

def is_value_int(value):
   #setting as int numerical values so ES can use these to work on reports
   try:
      value_is_int = int(value)
      return value_is_int	   
   except ValueError:
      return value
	 

##################
#Main Logic
##################
if config.USE_SLACK == True: notify_via_slack()
if config.USE_ES == True and fnm_action == "attack_details": update_es_index()
