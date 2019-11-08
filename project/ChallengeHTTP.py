from flask import Flask, request
import argparse

app = Flask(__name__)
response = ""

@app.route('/')
def index():
     return 'Hello world'

@app.route('/<path:domain_name_token>', methods = ['GET'])
def doHTTPChallenge(domain_name_token):
        print(response)
        return response

@app.route('/<path:domain_name_token>', methods = ['DELETE'])
def deleteHTTPChallenge(domain_name_token):
        global response
        response = ""
        return response

@app.route('/<path:domain_name_token>', methods = ['POST'])
def postHTTPChallenge(domain_name_token):
        global response
        #response = request.json['key']
        response = request.form['key']
        return response

def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('record')
    args = vars(parser.parse_args())
    #print('THE RECORD IS:' ,args.get('record'))
    #app.config['SERVER_NAME'] = args.get('record') + ':5002'
    app.run(host=args.get('record'), port=5002)
    #app.run()

if __name__ == "__main__":
    main()


#if __name__ == "__main__":
#        app.run(port=5002) #may need to add host to be equal to record