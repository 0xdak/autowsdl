# </> autowsdl

Autowsdl automates penetration testing of SOAP/XML type web services.

While performs tests to the target, also sends traffic to the specified proxy.
So you can easily see requests from Burp Suite and maybe go for Active Scan or perform your extensions :)
You can filter requests from Burp Suite by autowsdl_version by yuznumara 

The tool checks following vulnerabilities:
- TLS Unsupported
- Missing Authorization
- XML External Entity

## Usage

To test single url you can pass parameters or just pass a json file:

    ```python
        python3 autowsdl.py -url <target> /
                            -r <request_file> /
                            -H "Cookie:X,Authorization:Y" /
                            -m "POST" /
                            -p 127.0.0.1:8080 /
                            -sc 200,201 /
                            --debug
    ```

To test multiple urls you can pass JSON file:

    ```python
        python3 autowsdl.py -json wsdls.json
    ```

JSON file format has to be like below:

    ```json
        {
            "url": "http://target1.com",
            "request_file": "request_file_path.xml",
            "method": "GET",
            "headers": "Authorization: Basic qMjwmkokfqis==",
            "proxy": "127.0.0.1:8080",
            "status_codes": "",
            "debug": False,
        },
        {
            "url": "http://target2.com",
            "request_file": "request_file_path.xml",
            "method": "POST",
            "headers": "",
            "proxy": "",
            "status_codes": "",
            "debug": False,
        },
    ```
