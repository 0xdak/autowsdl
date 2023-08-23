from . import autowsdl
from . import webservice
# import webservice, autowsdl # for running from cli.py

import click
import logging
import json


###  BANNER ###################################

banner = """
                           __                          .___.__
        _____   __ ___/  |_  ______  _  ________ __| _/|  |  
        \__  \ |  |  \   __\/  _ \ \/ \/ /  ___// __ | |  |  
         / __ \|  |  /|  | (  <_> )     /\___ \/ /_/ | |  |__
        (____  /____/ |__|  \____/ \/\_//____  >____ | |____/
             \/                              \/     \/       

        {} by Ali Dak
______________________________________________________________
    """.format(webservice.VERSION)

### LOG SETTINGS #############################

LOG_FILENAME = "autowsdl.log"

logging.basicConfig(filename=LOG_FILENAME,
                    format='%(asctime)s %(message)s',
                    filemode='w')

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())

### VARIABLES ################################

headers_dict = {
    'User-Agent': 'autowsdl_{} by yuznumara'.format(webservice.VERSION)
}
##############################################


@click.command()
@click.option('-u', '--url', default=None,
              help='Target url with service/endpoint in it')
@click.option('-fj', '--from-json', default=None,
              help='Testing with parameters filled in json file')
@click.option('-r', '--request-file', default=None, type=click.File(mode='r'),
              help='Request file path')
@click.option('-H', '--headers', default=None,
              help='Set Headers split with \',\', format: -H "Cookie: X, Authorization: Y"')
@click.option('-ba', '--basic-auth', default=None,
              help="Basic Authorization credentials, format: username:password")
@click.option('-m', '--method', default="GET",
              help='HTTP Method, default GET')
@click.option('-p', '--proxy', default=None,
              help="Proxy, format: ip:port")
@click.option('-sc', '--success-codes', default=None,
              help="Default: 200, You can expand success codes list with comma")
@click.option('-d', '-v', '-vv', '-vvv', '--debug', '--verbose', is_flag=True, default=False,
              help="Debug mode, Verbose")
def main(url, from_json, request_file, headers, basic_auth, method, proxy, success_codes, debug):
    #  PARAMETER CONTROL - debug
    if debug:
        logger.setLevel(logging.DEBUG)
    ws_list = []

    try:
        if from_json is not None:
            f = open(from_json, 'r')
            data = f.read()
            json_data = json.loads(data)
            if isinstance(json_data, list):
                for i in json_data:
                    ws_list.append(webservice.WebService(from_json=i))
            elif isinstance(json_data, dict):
                ws_list.append(autowsdl.WebService(from_json=json_data))
        else:
            ws = webservice.WebService(url=url, from_json=from_json, request_file=request_file,
                            headers=headers, basic_auth=basic_auth, method=method, proxy=proxy, success_codes=success_codes)
            ws_list.append(ws)
    except Exception as e:
        logging.error(e)
    
    print(banner)

    for ws in ws_list:
        logger.critical(" :: URL           : "+ str(ws.url))
        logger.critical(" :: Method        : "+ str(ws.method))
        if ws.request_file:
            logger.critical(" :: Request File  : "+ str(ws.request_file))
        for i in list(ws.headers.keys()):
            logger.critical(" :: Header        : "+ i + ": " + str(ws.headers[i]))
        if ws.basic_auth:
            logger.critical(" :: Basic Auth    : "+ str(ws.basic_auth))
        logger.critical(" :: Success Codes : "+ str(ws.success_codes))
        if ws.proxies:
            for i in list(ws.proxies.keys()):
                logger.critical(" :: Proxy         : " + str(ws.proxies[i]))

        # print("______________________________________________________________")
        logger.critical("\n")

        response = None
        try:
            response = autowsdl.make_request(
                url=ws.url, request_body=ws.request_body, headers=ws.headers, method=ws.method, proxies=ws.proxies)
        except Exception as e:
            logger.error(e)
            continue

        # RESPONSE CONTROL - TO START TO THE TESTS, RESPONSE HAS TO BE SUCCESSFUL or not if param set
        if not autowsdl.check_response_success(response, success_codes=ws.success_codes):
            if autowsdl.check_response_unauth(response):
                logger.error("[!] " + str(response.status_code) +
                            " Unauthorized: Please provide credentials or authorization/cookie header.")
            else:  # TODO --force parametresi enabled sa buraya bakmicaksın
                logger.error("[*] " + str(response.status_code) +
                            " Response was not successful.")
            continue

        logger.info("[*] " + str(response.status_code) +
                    " Response was successful. Starting to the tests.")

        # STARTING TO THE TEST

        logger.info("[*] Checking the existence of TLS Unsupported")
        if autowsdl.check_ssl_vuln(response) == True:
            logger.critical("[+]" +
                            " Vulnerability Found: TLS Unsupported")
        else:
            logger.info("[-]" +
                            " Vulnerability Not Found: TLS Unsupported")

        logger.info("[*] Checking the existence of Authorization Vulnerability")
        if autowsdl.check_auth_vuln(response, ws) == True:
            logger.critical("[+]" +
                            " Vulnerability Found: Missing Authorization")
        else:
            logger.info("[-]" +
                            " Vulnerability Not Found: Missing Authorization")

        logger.info("[*] Checking the existence of XXE Vulnerability")
        if autowsdl.check_xxe_vuln(response, ws) == True:
            logger.critical("[+]" +
                            " Vulnerability Found: XXE Limited")
        else:
            logger.info("[-]" +
                            " Vulnerability Not Found: XXE Limited")
            
        print("______________________________________________________________")
        print()


if __name__ == "__main__":
    main()
