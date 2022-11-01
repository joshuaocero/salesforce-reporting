"""Authentication for salesforce-reporting"""
import requests
import xml.dom.minidom

from salesforce_reporting.exceptions import AuthenticationFailure

try:
    # Python 3+
    from html import escape
except ImportError:
    from cgi import escape


class RestConnection:
    """
    A Salesforce connection for accessing the Salesforce Analytics API using
    the RESTful API. This object is then used as the central
    object for passing report requests into Salesforce.

    By default the object assumes you are connection to a Production instance
    and using API v29.0 but both of these can be overridden to allow access to Sandbox
    instances and/or use a different API version.

    Parameters
    ----------
    client_id: string
        API ID/Key used to connect to SF
    client_secret: string
        API secret associated with the ID
    username: string
        Salesforce username used for this conneciton
    password: string
        Salesforce password attached to the username
    auth_url: string
        URL to be used to authenticate to saleforce
    api_version: string
        API version to use for this connection
    """

    def __init__(self, client_id=None, client_secret=None, username=None,
                    password=None, auth_url=None, api_version='v46.0'):
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.grant_type = 'password'
        self.api_version = api_version
        self.auth_url = auth_url

    def _get_login_headers(self):
        return {"Accept": "application/json",
                "Content-type": "application/json"}
    
    def _get_login_params(self):
        return {"client_id": self.client_id,
                "client_secret": self.client_secret,
                "username": self.username,
                "password": self.password,
                "grant_type": self.grant_type}
    
    def do_login(self):
        response = requests.post(self.auth_url,
                                 headers=self._get_login_headers(),
                                 params=self._get_login_params())
        
        if response.status_code not in [200, 201]:
            raise AuthenticationFailure(response.status_code, response.text)

        response_payload = response.json()
        return response_payload


class SoapConnection:
    """
    A Salesforce connection for accessing the Salesforce Analytics API using
    the Password/Token authentication. This object is then used as the central
    object for passing report requests into Salesforce.

    By default the object assumes you are connection to a Production instance
    and using API v29.0 but both of these can be overridden to allow access to Sandbox
    instances and/or use a different API version.

    Parameters
    ----------
    username: string
        the Salesforce username used for authentication
    password: string
        the Salesforce password used for authentication
    security_token: string
        the Salesforce security token used for authentication (normally tied to password)
    sandbox: boolean, default False
        whether or not the Salesforce instance connected to is a Sandbox
    api_version: string

    """

    def __init__(self, username=None, password=None, security_token=None, sandbox=False, api_version='v29.0'):
        self.username = username
        self.password = password
        self.security_token = security_token
        self.sandbox = sandbox
        self.api_version = api_version
        self.login_details = self.login(self.username, self.password, self.security_token)
        self.token = self.login_details['oauth']
        self.instance = self.login_details['instance']
        self.headers = {'Authorization': 'OAuth {}'.format(self.token)}
        self.base_url = 'https://{}/services/data/v31.0/analytics'.format(self.instance)

    @staticmethod
    def element_from_xml_string(xml_string, element):
        xml_as_dom = xml.dom.minidom.parseString(xml_string)
        elements_by_name = xml_as_dom.getElementsByTagName(element)
        element_value = None

        if len(elements_by_name) > 0:
            element_value = elements_by_name[0].toxml().replace('<' + element + '>', '').replace(
                '</' + element + '>', '')

        return element_value

    @staticmethod
    def _get_login_url(is_sandbox, api_version):
        if is_sandbox:
            return 'https://{}.salesforce.com/services/Soap/u/{}'.format('test', api_version)
        else:
            return 'https://{}.salesforce.com/services/Soap/u/{}'.format('login', api_version)

    def login(self, username, password, security_token):
        username = escape(username)
        password = escape(password)

        url = self._get_login_url(self.sandbox, self.api_version)

        request_body = """<?xml version="1.0" encoding="utf-8" ?>
        <env:Envelope
                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">
            <env:Body>
                <n1:login xmlns:n1="urn:partner.soap.sforce.com">
                    <n1:username>{username}</n1:username>
                    <n1:password>{password}{token}</n1:password>
                </n1:login>
            </env:Body>
        </env:Envelope>""".format(
            username=username, password=password, token=security_token)

        request_headers = {
            'content-type': 'text/xml',
            'charset': 'UTF-8',
            'SOAPAction': 'login'
        }

        response = requests.post(url, request_body, headers=request_headers)

        if response.status_code != 200:
            exception_code = self.element_from_xml_string(response.content, 'sf:exceptionCode')
            exception_msg = self.element_from_xml_string(response.content, 'sf:exceptionMessage')

            raise AuthenticationFailure(exception_code, exception_msg)

        oauth_token = self.element_from_xml_string(response.content, 'sessionId')
        server_url = self.element_from_xml_string(response.content, 'serverUrl')

        instance = (server_url.replace('http://', '')
                     .replace('https://', '')
                     .split('/')[0]
                     .replace('-api', ''))

        return {'oauth': oauth_token, 'instance': instance}
