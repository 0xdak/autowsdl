
import copy
import requests
import xml.etree.ElementTree as ET
import warnings
warnings.filterwarnings("ignore")

UNAUTHORIZED_CODES = [401, 403]


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
                                headers=headers, proxies=proxies, verify=False, timeout=5)
    else:  #  "POST"
        response = requests.post(
            url, data=request_body, headers=headers, proxies=proxies, verify=False, timeout=5)
    return response


def check_response_success(response: requests.Response, success_codes):
    '''
        check created response with given url and request_body if returns success
    '''
    if response.status_code in success_codes:
        return True

    return False


def check_response_unauth(response: requests.Response):
    '''
        check created response with given url and request_body if returns failure at authorization
    '''
    if response.status_code in UNAUTHORIZED_CODES:
        return True

    return False

def check_auth_vuln(response: requests.Response, ws):
    '''
        if decision is vulnerable so;
        if authorization header is not implemented, 
        so if the response not returns with 401 Unauthorized
        then return true 
    '''
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
        response.request.url, request_body=response.request.body, method=response.request.method, headers=headers, proxies=ws.proxies)
    if response_wo_auth.status_code in UNAUTHORIZED_CODES:
        return False

    return True


# appends cdata variables to all xml parameters
# and sends the request with this payload
# checks whether data is interpreted or not
def check_xxe_vuln(response: requests.Response, ws):
    if ws.method == "GET" or response.request.body == None:
        return False
    '''
        if cdata variable interprets and returns in response
        return True
    '''
    root = ET.fromstring(response.request.body)

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
                response.request.url, request_body=payload_result, method=response.request.method, headers=response.request.headers, proxies=ws.proxies)
            if 'autowsdl_by_yuznumara' in response_xxe.text:
                return True
        except Exception as e:
            print(e)
    return False


#TODO sslscan or sending request to the https://site and check is it alive
def check_ssl_vuln(response: requests.Response):
    '''
        if ssl is not implemented in request,
        then return true
    '''
    if response.url.startswith("https") is False:
        return True
    return False

