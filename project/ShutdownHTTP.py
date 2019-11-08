from flask import Flask, request
import argparse

app = Flask(__name__)

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@app.route('/shutdown')
def shutdown():
    shutdown_server()
    return 'ACME BYE BYE'

def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('record')
    args = vars(parser.parse_args())
    app.config['SERVER_NAME'] = args.get('record') + 5003
    #app.run(host=args.get('record'), port=5003)
    app.run()
if __name__ == "__main__":
    main()


