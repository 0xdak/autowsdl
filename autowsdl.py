
import copy
import requests
import click
import logging
import base64
import xml.etree.ElementTree as ET
import warnings
warnings.filterwarnings("ignore")

VERSION = "v1.0.0"

LOG_FILENAME = "autowsdl.log"
UNAUTHORIZED_CODES = [401, 403]
SUCCESS_CODES = [200, 201]

proxies = {
}

headers_dict = {
    'User-Agent': 'autowsdl_{} by yuznumara'.format(VERSION)
}

logging.basicConfig(filename=LOG_FILENAME,
                    format='%(asctime)s %(message)s',
                    filemode='w')

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())

def print_banner():
    print("""
                           __                          .___.__
        _____   __ ___/  |_  ______  _  ________ __| _/|  |  
        \__  \ |  |  \   __\/  _ \ \/ \/ /  ___// __ | |  |  
         / __ \|  |  /|  | (  <_> )     /\___ \/ /_/ | |  |__
        (____  /____/ |__|  \____/ \/\_//____  >____ | |____/
             \/                              \/     \/       

        {} by Ali Dak
______________________________________________________________
    """.format(VERSION))
    
def make_request(url, request_body=None, headers=None, method="GET", proxies=None):
    '''
        make request with given params
            GET -> url
            POST -> url, request_body, headers, method
        return response
    '''
    response = None
    if method == "GET":
        response = requests.get(url,
                                headers=headers, proxies=proxies, verify=False)
    else:  #  "POST"
        response = requests.post(
            url, data=request_body, headers=headers, proxies=proxies, verify=False)
    return response


def check_response_success(response: requests.Response):
    '''
        check created response with given url and request_body if returns success
    '''
    if response.status_code in SUCCESS_CODES:
        return True

    return False


def check_response_unauth(response: requests.Response):
    '''
        check created response with given url and request_body if returns failure at authorization
    '''
    if response.status_code in UNAUTHORIZED_CODES:
        return True

    return False


def check_ssl_vuln(response: requests.Response):
    '''
        if ssl is not implemented in request,
        then return true
    '''
    logging.info("[*] Checking the existence of TLS Unsupported")
    if response.url.startswith("https") is False:
        return True
    return False


def check_auth_vuln(response: requests.Response):
    '''
        if decision is vulnerable so;
        if authorization header is not implemented, 
        so if the response not returns with 401 Unauthorized
        then return true 
    '''
    logging.info("[*] Checking the existence of Authorization Vulnerability")
    if response.status_code in UNAUTHORIZED_CODES:
        return False

    headers = copy.deepcopy(response.request.headers)
    # tum auth header'lerini silerek tekrar request gonder donen response bak
    try:
        headers.pop("Authorization")
        headers.pop("Cookie")
    except:
        a = 1

    response_wo_auth = make_request(
        response.request.url, request_body=response.request.body, method=response.request.method, headers=headers, proxies=proxies)
    if response_wo_auth.status_code in UNAUTHORIZED_CODES:
        return False

    return True


# tüm parametrelere cdata değişkenini ekler.
def check_xxe_vuln(response: requests.Response):
    '''
        if cdata variable interprets and returns in response
        return True
    '''
    logging.info("[*] Checking the existence of XXE Vulnerability")
    root = ET.fromstring(response.request.body)

    xxe_body = response.request.body
    xxe_payload = "<!DOCTYPE root [<!ENTITY param_yuznumara 'autowsdl_by_yuznumara'>]>\r\n"
    param_name = "ampersant_here_param_yuznumara;"

    for i in range(len(list(root.iter()))):
        try:
            root_tmp = copy.deepcopy(root)
            all_elements_tmp = list(root_tmp.iter())
            all_elements_tmp[i].text = all_elements_tmp[i].text + param_name
            updated_xml = ET.tostring(
                root_tmp, encoding="utf-8").decode("utf-8")

            payload_result = xxe_payload + \
                updated_xml.replace("ampersant_here_", "&")
            response_xxe = make_request(
                response.request.url, request_body=payload_result, method=response.request.method, headers=response.request.headers, proxies=proxies)
            if 'autowsdl_by_yuznumara' in response_xxe.text:
                return True
        except:
            _ = 1
    return False


@click.command()
@click.option('-u', '--url', default=None, required=True,
              help='Target url with service/endpoint in it')
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
@click.option('-d', '-v', '-vv', '-vvv', '--debug', '--verbose', is_flag = True,
              help="Debug mode, Verbose")
def main(url, request_file, headers, basic_auth, method, proxy, success_codes, debug):
    # PRINT BANNER
    print_banner()

    # PARAMETER CONTROL - proxy
    if proxy is not None:
        proxies["http"] = "http://" + proxy
        proxies["https"] = "https://" + proxy

    # PARAMETER CONTROL - request_file
    try:
        request_body = ""
        if request_file is not None:
            request_body = request_file.read()
    except:
        logging.error("ERR: Error while reading request_file parameter")

    #  PARAMETER CONTROL - headers
    try:
        if headers is not None:
            for header in headers.split(','):
                header_sp = header.split(':')
                headers_dict[header_sp[0].strip()] = header_sp[1].strip()
    except:
        logging.error(
            "ERR: Error while parsing headers parameter, Continuiung without header information.")

    # PARAMETER CONTROL - basic_auth
    try:
        if basic_auth is not None:
            headers_dict["Authorization"] = "Basic " + \
                base64.b64encode(basic_auth.encode("ascii")).decode()
    except:
        logging.error(
            "ERR: Error while parsing basic_auth parameter, Continuiung without basic auth information.")

    #  PARAMETER CONTROL - success_codes
    try:
        if success_codes is not None:
            [SUCCESS_CODES.append(int(i)) for i in success_codes.split(',')]
    except:
        logging.error(
            "ERR: Error while parsing success_codes parameter, Continuiung without adding success status codes.")

    print(" :: URL          :", url)
    print(" :: Method       :", method)
    if request_file:
        print(" :: Request File :", request_file.name)
    for i in list(headers_dict.keys()):
        print(" :: Header       :", i + " :" + headers_dict[i])
    if basic_auth:
        print(" :: Basic Auth   :", basic_auth)
    if proxy:
        print(" :: Proxy        :", proxy, "(http/https)")
    print(" :: Debug Mode   :", debug)
        
    print("______________________________________________________________")
    print()

    # PARAMETER CONTROL - debug
    if debug:
        logger.setLevel(logging.DEBUG)

    response = make_request(
        url=url, request_body=request_body, headers=headers_dict, method=method, proxies=proxies)


    # RESPONSE CONTROL - TO START TO THE TESTS, RESPONSE HAS TO BE SUCCESSFUL or not if param set
    if not check_response_success(response):
        if check_response_unauth(response):
            logger.error("[!] " + str(response.status_code) +
                         " Unauthorized: Please provide credentials or authorization/cookie header.")
        else:  # TODO --force parametresi enabled sa buraya bakmicaksın
            logger.error("[*] " + str(response.status_code) +
                         " Response was not successful.")
        return

    logger.info("[*] " + str(response.status_code) +
                " Response was successful. Starting to the tests.")

    # STARTING TO THE TEST

    # TODO sslscan
    if check_ssl_vuln(response) == True:
        logger.critical("[+]" +
                        " TLS Unsupported")

    if check_auth_vuln(response) == True:
        logger.critical("[+]" +
                        " Missing Authorization")

    if check_xxe_vuln(response) == True:
        logger.critical("[+]" +
                        " XXE")



if __name__ == "__main__":
    main()
