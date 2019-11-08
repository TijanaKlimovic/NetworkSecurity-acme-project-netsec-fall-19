from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import json, base64, hashlib,requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding,utils
from cryptography import x509
from cryptography.x509.oid import NameOID

class ACME_client:

    def __init__(self, dir):
        self.accountURL = None
        self.orderURL = None
        self.finalizeURL = None
        self.authorizations = None # URL to the authorization objects
        self.jwk = None #jwk value
        self.auth = None #authorization objects
        self.generateKeys()
        self.getDirectory(dir)
        self.getNonce()
        self.getAccount()
        #create account on server

    def getAccount(self):
        payload = {'termsOfServiceAgreed':True}
        r = self.sendRequest(self.getURL('newAccount'), payload)
        #print(r.headers)
        self.accountURL = r.headers['Location'] #get URL of account obj
        print("Account is at: ", self.accountURL)

    def generateKeys(self):
        self.private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = default_backend())
        self.public_key = self.private_key.public_key()

    def encode_b64(self, b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    def getURL(self,string):
        return self.dictionary.get(string)

    def getDirectory(self, url='https://localhost:14000/dir'):
        r = requests.get(url, verify="pebble_https_ca.pem")
        self.dictionary = r.json()

    def getNonce(self):
        r = requests.head(self.getURL("newNonce"), verify="pebble_https_ca.pem") #get the new nonce
        self.nonce = r.headers['Replay-Nonce']

    #send post request to url , by default acts as post as get
    def sendRequest(self, url, payload="", headers={'Content-Type': 'application/jose+json'}):
        while True:
            body = self.makeRequestBody(url, payload)
            #headers = {'Content-Type': 'application/jose+json'}
            r = requests.post(url, data=body, headers=headers, verify="pebble_https_ca.pem")
            self.nonce = r.headers['Replay-Nonce'] #update nonce
            if r.status_code==200 or r.status_code==201:
                break
            else:
                print(r.text)
        return r

    def makeRequestBody(self, url, payload):
        if payload != "":
            enc64_payload = self.encode_b64(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf8'))
        else:
            enc64_payload = ""

        if self.accountURL is None: #the account doesn't exist yet
            n = self.public_key.public_numbers().n
            e = self.public_key.public_numbers().e
            self.jwk = {"kty": "RSA",
                   "n": self.encode_b64(n.to_bytes((n.bit_length() + 7) // 8, 'big')),
                   "e": self.encode_b64(e.to_bytes((e.bit_length() + 7) // 8, 'big'))
                   }
            protectedHeader = {"alg": 'RS256', "url": url, "nonce": self.nonce, "jwk": self.jwk}
        else:
            protectedHeader = {"alg": 'RS256', "url": url, "nonce": self.nonce, "kid": self.accountURL}

        enc64_protectedHeader = self.encode_b64(json.dumps(protectedHeader, separators=(',', ':'), sort_keys=True).encode('utf8'))

        protected_input = "{}.{}".format(enc64_protectedHeader, enc64_payload).encode('utf8')
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash, default_backend())
        hasher.update(protected_input)
        digest = hasher.finalize()
        signature = self.private_key.sign(digest, padding.PKCS1v15(), utils.Prehashed(chosen_hash))
        enc64_signature = self.encode_b64(signature)
        body = json.dumps({"protected": enc64_protectedHeader, "payload": enc64_payload, "signature": enc64_signature}, separators=(',', ':'), sort_keys=True).encode('utf8')
        #print(body)
        return body

    def sendCSR(self,url,csr):
        while True:
            enc64_csr = self.encode_b64(csr) #a string
            payload = {"csr":enc64_csr}
            enc64_payload = self.encode_b64(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf8'))
            protectedHeader = {"alg": 'RS256', "url": url, "nonce": self.nonce, "kid": self.accountURL}
            enc64_protectedHeader = self.encode_b64(json.dumps(protectedHeader, separators=(',', ':'), sort_keys=True).encode('utf8'))
            protected_input = "{}.{}".format(enc64_protectedHeader, enc64_payload).encode('utf8')

            chosen_hash = hashes.SHA256()
            hasher = hashes.Hash(chosen_hash, default_backend())
            hasher.update(protected_input)
            digest = hasher.finalize()
            signature = self.private_key.sign(digest, padding.PKCS1v15(), utils.Prehashed(chosen_hash))
            enc64_signature = self.encode_b64(signature)
            body = json.dumps({"protected": enc64_protectedHeader, "payload": enc64_payload, "signature": enc64_signature},\
                              separators=(',', ':'), sort_keys=True).encode('utf8')
            headers = {'Content-Type': 'application/jose+json'}

            r = requests.post(url, data=body, headers=headers, verify="pebble_https_ca.pem")
            self.nonce = r.headers['Replay-Nonce'] #update nonce
            if r.status_code==200 or r.status_code==201:
                break
            else:
                print(r.text)
        return r

    def submitOrder(self,identifiers):
        payload = {'identifiers': identifiers}
        r = self.sendRequest(self.getURL('newOrder'), payload)
        order = r.json()
        self.orderURL = r.headers['Location'] #get URL of order obj -> to be polled after challenges are complete
        #print(order)
        self.finalizeURL = order.get('finalize') #get finalize url to send the CSR to
        self.authorizations = order.get('authorizations')
        #print("Authorizations are ", self.authorizations, "and are of type ", type(self.authorizations))
        #return self.fetchAuthorizationObjs()
        return self.authorizations

     #POST-AS-GET request for the authorization objs
    def fetchAuthorizationObjs(self):
        auth_objs = [None]*len(self.authorizations)
        i=0
        for url in self.authorizations:
            auth_objs[i]=self.sendRequest(url).json()
            print("AUTHORIZATION OBJECT IS:", auth_objs[i])
            i=i+1

        self.auth = auth_objs #return an array of authorization objs containing a challenges for each domain associate to cert
        return auth_objs

    #make key authorization for given token
    def createKeyAuthorization(self,token): #use self.jwk
        accountkey = json.dumps(self.jwk, sort_keys=True, separators=(',', ':'))
        thumbprint = self.encode_b64(hashlib.sha256(accountkey.encode('utf8')).digest()) #hash the account key
        keyauthorization = "{}.{}".format(token, thumbprint)
        return keyauthorization

    def makeCSR(self, identifiers):
        # Generate a CSR
        '''
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),\
               x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),\
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),\
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),\
               x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),\
            ])).add_extension(x509.SubjectAlternativeName([\
                x509.DNSName(u"mysite.com"),\
                x509.DNSName(u"www.mysite.com"),\
                x509.DNSName(u"subdomain.mysite.com"),\
            ]),
        critical = False,).sign(self.private_key, hashes.SHA256(), default_backend())
        csr.public_bytes(serialization.Encoding.DER)
        '''
        print("IDENTIFIERS ARE: ", identifiers, "and are of type ", type(identifiers))
        alternatives = [None]*len(identifiers) #create array to suit csr format
        for i in range(len(identifiers)):
            alternatives[i] = x509.DNSName(identifiers[i])

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),]))

        builder = builder.add_extension(x509.SubjectAlternativeName(alternatives),critical=False,)
        request = builder.sign(self.private_key, hashes.SHA256(), default_backend())
        csr = request.public_bytes(serialization.Encoding.DER)
        return csr

    def revoke(self, certificate):
        while True:
            url = self.getURL('revokeCert')
            cert = x509.load_pem_x509_certificate((certificate.text).encode('utf-8'), default_backend())
            payload = {"certificate" : self.encode_b64(cert.public_bytes(serialization.Encoding.DER))}
            enc64_payload = self.encode_b64(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf8'))
            protectedHeader = {"alg": 'RS256', "url": url, "nonce": self.nonce, "kid": self.accountURL}
            enc64_protectedHeader = self.encode_b64(json.dumps(protectedHeader, separators=(',', ':'), sort_keys=True).encode('utf8'))

            protected_input = "{}.{}".format(enc64_protectedHeader, enc64_payload).encode('utf8')
            chosen_hash = hashes.SHA256()
            hasher = hashes.Hash(chosen_hash, default_backend())
            hasher.update(protected_input)
            digest = hasher.finalize()
            signature = self.private_key.sign(digest, padding.PKCS1v15(), utils.Prehashed(chosen_hash))
            enc64_signature = self.encode_b64(signature)
            body = json.dumps(
                {"protected": enc64_protectedHeader, "payload": enc64_payload, "signature": enc64_signature}, \
                separators=(',', ':'), sort_keys=True).encode('utf8')
            headers = {'Content-Type': 'application/jose+json'}

            r = requests.post(url, data=body, headers=headers, verify="pebble_https_ca.pem")
            self.nonce = r.headers['Replay-Nonce']  # update nonce
            if r.status_code == 200 or r.status_code == 201:
                break
            else:
                print(r.text)
        print(r)
        return r

