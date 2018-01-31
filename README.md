# FastNetMon-Elasticsearch-Plugin
Small plugin to allow storage of FastNetMon reported data to ES, also includes the SLACK notification functionality
####
__*Work in progress*__
####

I wanted to be able to store FNM report data and traffic samples to ES so I could create graphical reports easily using Kibana-
This program allows to store reports from FastNetMon towards an Elasticsearch cluster. It's just a callable script, when there's an attack it's called and it extracts all the data FNM produces, then it parses the data and stores it on ES.

**Installation**

1.- Python3 is required

2.- Install Elasticsearch and geoip2 from pip
pip3 install Elasticsearch
pip3 install geoip2

3.- Clone this repository and change the "config.py" variables to suit your environment 

4.- Edit /etc/fastnetmon.conf and set the attribute "notify_script_path" to point fnm_es.py executable

This script is still being tested and there's a lot to be done







*This product includes GeoLite2 data created by MaxMind, available from
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.*
