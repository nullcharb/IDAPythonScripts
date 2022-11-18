import requests
from dumpulator import Dumpulator

def hunt_hash(hash_value, api_url='https://hashdb.openanalysis.net', timeout = 60):

    types = {
        "binary": 2,
        "octal": 8,
        "decimal": 10,
        "hex": 16
    }
        
    hash_value_int = int(hash_value, types['hex'])
    print(hash_value_int)
    matches = []
    hash_list = [hash_value_int]
    module_url = api_url + '/hunt'
    r = requests.post(module_url, json={"hashes": hash_list}, timeout=timeout)
    if not r.ok:
        print(module_url)
        print(hash_list)
        print(r.json())
        # raise HashDBError("Get hash API request failed, status %s" % r.status_code)
    for hit in r.json().get('hits',[]):
        algo = hit.get('algorithm',None)
        if (algo != None) and (algo not in matches):
            matches.append(algo)
    # return matches


def hash_to_api(hash_value, api_url='https://hashdb.openanalysis.net', timeout = 60, algorithm="carbanak"):

    types = {
        "binary": 2,
        "octal": 8,
        "decimal": 10,
        "hex": 16
    }
        
    hash_value_int = int(hash_value, types['hex'])
    # https://hashdb.openanalysis.net/hash/carbanak/175451598
    module_url = api_url + '/hash/' + algorithm + "/" + str(hash_value_int)
    r = requests.get(module_url, timeout=timeout)
    if not r.ok:
        print(module_url)
        print(r.json())
        return ""
        # raise HashDBError("Get hash API request failed, status %s" % r.status_code)
    else:
        return r.json()['hashes'][0]['string']['api']


dp = Dumpulator("zloader.dmp")
# temp_addr = dp.allocate(256)
result = dp.call(0x311D990)
print(hex(result))
# print(hash_to_api(hash_value=hex(result)[2:], algorithm="carbanak"))