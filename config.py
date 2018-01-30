#Variables setup
#ElasticSearch variables
USE_ES = True
#Index must be lowercase
ES_INDEX = "fastnetmon"
ES_SERVER_IP = "172.16.0.4"
ES_SERVER_PORT = 9200
ES_USERNAME = None
ES_PASSWORD = None
ES_DOCTYPE = 'ddos_report'
#Due to the amount of information, this is saved in a different table and we relate it to an attack using and ID
#Not everyone uses or wants this so it's disabled by default
ES_EXPORT_TRAFFIC_SAMPLE = False
ES_TRAFFIC_SAMPLE_INDEX = "FNM_traffic_sample"
ES_TRAFFIC_SAMPLE_INDEX_TYPE = "fnm_traffic_sample"

#SLACK VARIABLES
#If you want to receive SLACK alerts, it's based on Pavel's notify script, does the same thing
USE_SLACK = True
SLACK_URL = "https://hooks.slack.com/services/AAAAAAAAAAAAAAAAAAAAAAAAA"
SLACK_TITLE = "FastNetMon Alert"
DETAILS_TO_SLACK = True

#FastNetMon arguments
FNM_NETWORK_ACCOUNTING = False

#GeoDB config
CITY_GEO_DB = "geoipdbs/GeoLite2-City.mmdb"
ASN_GEO_DB = "geoipdbs/GeoLite2-ASN.mmdb"
