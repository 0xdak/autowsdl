# </> autowsdl

`autowsdl` automates penetration testing of SOAP/XML type web services. It can be used as a helper automatize tool.

While performs tests to the target, it also sends traffic to the specified proxy.
So you can easily see requests from Burp Suite and maybe go for Active Scan or use your extensions on it :)
You can filter requests in Burp Suite by autowsdl_version by yuznumara.

The tool checks following vulnerabilities:
- TLS Unsupported
- Missing Authorization
- XML External Entity

## Installation

Install from GitHub directly:

```
git clone https://github.com/0xdak/autowsdl
cd autowsdl
pip3 install -r requirements.txt
python3 setup.py install
```

## Usage

`$ autowsdl -u <target>` 

or 

`$ autowsdl --from-json <json_file>`

- `-u` / `--url`: target url
- `-fj` / `--from-json`: it is used to perform multiple tests without the need for typing parameters.
- `-r` / `--request_file`: request file path
- `-H` / `--header`: specified headers like Cookie...
- `-ba` / `--basic-auth`: basic authorization credentials seperated as user:pass
- `-m` / `--method`: http method, default is GET
- `-p` / `--proxy`: proxy, it enables http and https for given proxy
- `-sc` / `--success-codes`: success codes, default [200, 201]
- `-d` / `--debug`: debug/verbose mode, prints verbose messages

### To test single url you can pass parameters or just pass a json file:

```bash
autowsdl -u <target> /
         -r <request_file> /
         -H "Cookie:X,Authorization:Y" /
         -m "POST" /
         -p 127.0.0.1:8080 /
         -sc 200,201 /
         --debug
```

### To test multiple urls you can pass JSON file:

```bash
autowsdl --from-json wsdls.json
```

JSON file format has to be like below:

```json
[
    {
        "url": "http://target1.com",
        "method": "GET",
        "headers": "Authorization: Basic qMjwmkokfqis==",
        "proxy": "127.0.0.1:8080",
        "status_codes": "",
    },
    {
        "url": "http://target2.com",
        "request_file": "request_file_path.xml",
        "method": "POST",
        "basic_auth": "user:pass",
        "headers": "",
        "proxy": "",
        "status_codes": ""
    }   
]
```
