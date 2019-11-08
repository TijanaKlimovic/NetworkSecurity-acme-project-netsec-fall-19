from flask import Flask
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import argparse

app = Flask(__name__)

@app.route('/')
def index():
    with open("cert_file" , "r") as certificate:
        return certificate.read()

def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('record')
    args = vars(parser.parse_args())
    #app.config['SERVER_NAME'] = args.get('record') + ':5001'
    app.run(host=args.get('record'), port=5001, ssl_context=("cert_file", "key_file"))
    #app.run(ssl_context=("cert_file", "key_file"))

if __name__ == "__main__":
    main()

'''
if __name__ == "__main__":
    app.run(port=5001, ssl_context=("cert_file", "key_file"))
'''