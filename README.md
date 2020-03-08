# shitsniffer
Gather a list of Citrix appliances in a country / state pair, and check if they're vulnerable to CVE-2019-19781

It does this by querying Shodan for all results in a particular country matching a search string. By default, it searches `country:AU has_ssl:true` with the search string `"Set-Cookie: pwcount=0"`

To check for vulnerability, we see if a `HEAD` for `https://<HOST>/vpn/%2E%2E/vpns/cfg/smb.conf` returns a status `200`. This means directory traversal is allowed, and the patch or workaround has not been applied to the host.

## Setup
You'll need to download the GeoLite2 ASN and City DBs, which will resolve details on discovered hosts. You can find the downloads here: https://dev.maxmind.com/geoip/geoip2/geolite2/

Place the .mmdb files into a folder named geolite under where you extracted shitsniffer.py

## Usage
```
usage: shitsniffer.py [-h] [-t TARGETHOST] [-f RESULTSFILE] [-d DATAFILE]
                      [-a APIKEY] [-c COUNTRY] [-s SEARCHSTRING] [-n]
                      [-l LIMIT]

OPTIONS:
  -h, --help            show this help message and exit
  -t TARGETHOST, --targethost TARGETHOST
                        Host to check, will scan shodan if not specified
  -f RESULTSFILE, --resultsfile RESULTSFILE
                        Where to save the scanner output json file
  -d DATAFILE, --datafile DATAFILE
                        Path to save/load shodan data file (saves query
                        credits)
  -a APIKEY, --apikey APIKEY
                        Your shodan.io API key
  -c COUNTRY, --country COUNTRY
                        Country to search
  -s SEARCHSTRING, --searchstring SEARCHSTRING
                        Additional search arguments
  -n, --no-color        Output without color
  -l LIMIT, --limit LIMIT
                        Process this many hosts from shodan data

Example: python shitsniffer.py -a <API key> -d shodan-DDMMYY.json -f output-DDMMYY.json
```
