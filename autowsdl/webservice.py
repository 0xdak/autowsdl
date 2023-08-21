import base64
import copy
import io

VERSION = "v1.1.0"

headers_default = {
    'User-Agent': 'autowsdl_{} by yuznumara'.format(VERSION)
}

SUCCESS_CODES = [200, 201]

#  consists of error handling of the user supplied params
class WebService():
    def __init__(self, url=None, from_json=None, request_file=None, headers=headers_default, basic_auth=None, method="GET", proxy="", success_codes=SUCCESS_CODES):
        if from_json:
            self.load_from_json(from_json)
        else:
            self.url = self.set_url(url)
            self.request_file = request_file
            self.request_body = self.set_request_body(request_file)
            self.headers = self.set_headers(headers)
            self.basic_auth = self.set_basic_auth(basic_auth)
            self.method = self.set_method(method)
            self.proxies = self.set_proxies(proxy)
            self.success_codes = self.set_success_codes(success_codes)

    def set_url(self, url):
        return url

    def set_request_body(self, request_file):
        if request_file is not None:
            try:
                if isinstance(request_file, io.TextIOWrapper):
                    return request_file.read()
                elif isinstance(request_file, str):
                    f = open(request_file, 'r')
                    return f.read()
            except:
                return None
        return None

    def set_headers(self, headers):
        headers_d = copy.deepcopy(headers_default)
        try:
            for header in headers.split(','):
                header_sp = header.split(':')
                headers_d[header_sp[0].strip()] = header_sp[1].strip()
            return headers_d
        except:
            return headers_d

    def set_basic_auth(self, basic_auth):
        try:
            self.headers["Authorization"] = "Basic " + \
                base64.b64encode(basic_auth.encode("ascii")).decode()
            return basic_auth
        except:
            return None

    def set_method(self, method):
        return method

    def set_proxies(self, proxy):
        if proxy is "":
            return None
        try:
            proxies_dict = {}
            proxies_dict["http"] = "http://" + proxy
            proxies_dict["https"] = "https://" + proxy
            return proxies_dict
        except:
            return None

    def set_success_codes(self, success_codes):
        sc_codes = copy.deepcopy(SUCCESS_CODES)
        if success_codes == None:
            return sc_codes
        if success_codes.split(',') == [''] or success_codes == None or success_codes == '':
            return sc_codes
        for i in success_codes.split(','):
            sc_codes.append(int(i))
        return list(set(sc_codes))

    # type(from_json) is dict!
    def load_from_json(self, from_json: dict):
        try:
            self.url = self.set_url(from_json.get("url"))
            self.request_file = from_json.get("request_file")
            self.request_body = self.set_request_body(from_json.get("request_file"))
            self.headers = self.set_headers(from_json.get("headers"))
            self.basic_auth = self.set_basic_auth(from_json.get("basic_auth"))
            self.method = self.set_method(from_json.get("method"))
            self.proxies = self.set_proxies(from_json.get("proxy"))
            self.success_codes = self.set_success_codes(from_json.get("success_codes"))
        except Exception as e:
            print("hata",e)



