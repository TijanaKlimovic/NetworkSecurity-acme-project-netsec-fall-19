import argparse, time, subprocess ,requests
import multiprocessing

from cryptography.hazmat.primitives import serialization

from ACME_client import ACME_client
from DNS_server import Resolver
import hashlib


def parseArgs():

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('challenge')
    parser.add_argument('--dir', required=True)
    parser.add_argument('--record', required=True)
    parser.add_argument('--domain', action='append', required=True)
    parser.add_argument('--revoke', action="store_true", required=False)
    args = vars(parser.parse_args()) #create dictionary with argument names as keys and their values
    for k in args.keys():
        print(k, args.get(k))
    return args

if __name__ == '__main__':

    #START SERVICES
    args = parseArgs()
    acme = ACME_client(args.get('dir'))
    dns = Resolver(args.get('record'))
    dns.start()

    print("")

    #DNS_server = subprocess.Popen(['python', 'DNS_server.py', args.get('record')])
    Chall_http_server = subprocess.Popen(['python', "ChallengeHTTP.py",args.get('record')])
    Shutdown_server = subprocess.Popen(['python', "ShutdownHTTP.py",args.get('record')])

    config = {'host': args.get('record'), 'port': 5002}
    #Chall_http_server = multiprocessing.Process(target=ChallengeHTTP.start_server(args.get('record')),kwargs=config)

    #PREPARE PAYLOAD FOR ORDER
    identifiers = [None]*len(args.get('domain'))
    for k in range(len(identifiers)):
        identifiers[k] = {'type':'dns', 'value': args.get('domain')[k]}
    for k in identifiers:
        print(k)
    #SEND ORDER AND OBTAIN AUTHORIZATION URLS
    auth_URL_list = acme.submitOrder(identifiers)

    #OBTAIN AUTHORIZATION OBJECTS CORRESPONDING TO EACH AUTHORIZATION URL WITH ORDER MAINTAINED
    auth_obj = acme.fetchAuthorizationObjs()

    #decide on challenge and post all required data to desired location
    # DO DNS-01 CHALLENGE
    if args.get('challenge') == 'dns01':
        for i in range(len(auth_obj)):
            domain = auth_obj[i].get('identifier').get('value')
            challengeArray = auth_obj[i].get('challenges')

            token = None
            challengeURL = None
            # find the token and url corresponding to dns challenge of auth_obj[i]
            for j in challengeArray:
                if j.get('type') == 'dns-01':
                    token = j.get('token')
                    challengeURL = j.get('url')
                    break

            key = acme.createKeyAuthorization(token)
            key = acme.encode_b64(hashlib.sha256(key.encode('utf8')).digest())
            TXTdomain = "_acme-challenge." + domain
            # PROVISION THE TEXT RECORD IN DNS
            dns.updateTXT(key, TXTdomain)

            # for each auth obj send post as get request to challengeURL
            r = acme.sendRequest(challengeURL, payload={}, headers={'Content-type': 'application/jose+json', "User-Agent": "Tijana"})
            # print(challengeURL)
            print("CHALLENGE SENT: ", r.text)

            response = acme.sendRequest(acme.authorizations[i])
            while response.json()['status'] != 'valid':
                time.sleep(2)
                response = acme.sendRequest(acme.authorizations[i])
                print(response.text)
            #print("AUTHORIZATION IS VALID!")

    else:
        #DO HTTP-01 CHALLENGE
        for i in range(len(auth_obj)):

            print("AUTHORIZATION OBJECT IS: ", auth_obj[i])
            domain = auth_obj[i].get('identifier').get('value')
            challengeArray = auth_obj[i].get('challenges')

            print("CHALLENGE ARRAY IS: ", challengeArray)
            token = None
            challengeURL = None

            # find the token and url corresponding to http challenge of auth_obj[i]
            for j in challengeArray:
                if j.get('type') == 'http-01':
                    token = j.get('token')
                    challengeURL = j.get('url')
                    break

            key = acme.createKeyAuthorization(token)
            #url = 'http://' + args.get('record') + ':5002/'+ domain + "/.well-known/acme-challenge/" + token
            url = 'http://' + args.get('record') + ':5002/' + "/.well-known/acme-challenge/" + token

            print("!!!!!!!!! I AM POSTING TO HTTP THE CHALLENGE TO ", url)

            requests.post(url, data={'key': key}, verify=False)


            #for each auth obj send post as get request to challengeURL
            r = acme.sendRequest(challengeURL, payload={} , headers= {'Content-type': 'application/jose+json', "User-Agent" : "Tijana"})
            #print(challengeURL)
            #print("CHALLENGE SENT: ", r.text)

            response = acme.sendRequest(acme.authorizations[i])

            print("!!!!!!!!! THE ACME SERVER TRIES TO VERIFY NOW !!!!!!!!!!")

            while response.json()['status'] != 'valid':
                time.sleep(2)
                response = acme.sendRequest(acme.authorizations[i])
                print(response.text)

    r = acme.sendRequest(acme.orderURL) #send post-as-get request to order obj url
    while r.json().get('status') != 'ready':
        #time.sleep(1)
        r = acme.sendRequest(acme.orderURL)
    print('ready for finalization!!!!')

    #create CSR and send csr to ca
    csr = acme.makeCSR(args.get('domain'))
    r = acme.sendCSR(acme.finalizeURL, csr)
    print(r.text)

    #POLL UNTIL ORDER OBJECT LEAVES THE PROCESSING AND GOES INTO VALID STATE
    r = acme.sendRequest(acme.orderURL)
    while r.json()['status']!='valid':
        time.sleep(2)
        r = acme.sendRequest(acme.orderURL)
    print(r.text)

    #GET THE URL OF CERTIFICATE
    certURL = r.json()['certificate']
    cert = acme.sendRequest(certURL)
    print(cert.text)

    #STORE PRIVATE KEY AND CERT TO DISK
    with open("key_file", "wb") as pkey:
        pkey.write(acme.private_key.private_bytes(\
        encoding = serialization.Encoding.PEM, \
        format = serialization.PrivateFormat.TraditionalOpenSSL, \
        encryption_algorithm = serialization.NoEncryption()))

    with open("cert_file", "w") as certificate:
        certificate.write(cert.text)

    #START HTTPS SERVER WITH OBTAINED CERTIFICATE
    HTTPS_server = subprocess.Popen(['python', "CertifficateHTTPS.py",args.get('record')])

    #IF REVOKE IS PRESENT WE MUST REVOKE CERTIFICATE BEFORE SHUTTING DOWN APPLICATION
    if args.get('revoke'):
        print("REVOKE IS SET")
        acme.revoke(cert)
    else:
        print("REVOKE NOT SET")

    #when ShutdownHTTP.py process exited kill all other subprocesses
    Shutdown_server.wait()  
    Chall_http_server.kill()
    HTTPS_server.kill()




