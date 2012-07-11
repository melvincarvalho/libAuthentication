<?php
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_X509CertRepo.php
// Date       : 26th Mar 2010
//
// Copyright 2008-2010 foaf.me
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//
// "Everything should be made as simple as possible, but no simpler."
// -- Albert Einstein
//
//-----------------------------------------------------------------------------------------------------------------------------------


/**
 * An X509Certificate repository
 *
 * @author László Török
 */
class Authentication_X509CertRepo
{
    const DEFAULT_IDP = 'foafssl.org';
    
    private $IDPCertificates = array ( self::DEFAULT_IDP =>
"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhFboiwS5HzsQAAerGOj8
Zk6qvEf2QVarlm+c1fxd6f3OoQ9ezib1LjXitw+z2xcLG8lzaTmKOU0jw7KZp6WL
W6gqhAWj2BQ1Lkl9R7aAUpA3ypk52gik8u/5JiWpTt1EV99DP5XNzzQ/QVjkvBlj
rY+1ZeM+XtKzGfbK7eWh583xn3AE6maprXfLAo3BjUWJOQe0VHGYgrBVOcRQrSQ6
34/f+jk22tmYZRzdTT/ZCadeLd7NryIeJbEu0W105JYvKodawSM3/zjt4fXFIPyB
z8vHHmHRd2syDWqUy46YVQfqCfUBdXkHbvVQBtAfvRGUhYbFQm926an6z9uRE5LC
aQIDAQAB
-----END PUBLIC KEY-----
",

/* now obsolete
				       'auth.fcns.eu' =>
"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfLj5x7XR+v07NgOCtOc
KJgMkq7p1rEvSQ9jfTFYDcL454wv4QFS6OLnkH6KpV61npj0XYznYycgmNvWw9cD
RdhN+fLW0VKqSRYqNAkvSc1JkmW9JisldX33iTiyhVoEDfviu9pMBImalZ1y14A4
LPHAkV5rZy/fRk7F/gMo29JuLSmPngu4ze/+oHHp1+EiIlhMi8exisQvVhhc9n2C
RWL5eYmG9Qr90C1nJnMygDKraTFj3CxStk0HN5NhNYKe1kNFElny9hLxlpL8D0Ul
VYhfC0gRHc6mTRB3NEfSmkQCWJCR1iV9ZrMFD5fO27w5AkMIN4AULUMNxLed3KmC
1QIDAQAB
-----END PUBLIC KEY-----
" */
                                       'auth.my-profile.eu' =>
"-----BEGIN CERTIFICATE-----
MIIHKzCCBhOgAwIBAgIDBerZMA0GCSqGSIb3DQEBBQUAMIGMMQswCQYDVQQGEwJJ
TDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0
YWwgQ2VydGlmaWNhdGUgU2lnbmluZzE4MDYGA1UEAxMvU3RhcnRDb20gQ2xhc3Mg
MSBQcmltYXJ5IEludGVybWVkaWF0ZSBTZXJ2ZXIgQ0EwHhcNMTIwNDA0MTA0NTEw
WhcNMTMwNDA0MTg1MjI3WjBuMRkwFwYDVQQNExBoWTdENnQ3M1A5Y1B2ckF6MQsw
CQYDVQQGEwJGUjEbMBkGA1UEAxMSYXV0aC5teS1wcm9maWxlLmV1MScwJQYJKoZI
hvcNAQkBFhhwb3N0bWFzdGVyQG15LXByb2ZpbGUuZXUwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC9Ix5SIxwgZjGvx63VXYhFU2+A94FXEO7qr1Ri1ZdZ
WUjItBUNvK6JzdFA1oAPYtGMDs/Uev99Ibj4FfUT3R2GYI2WWv1nGZk6zXFN51Z3
2JAXh1XgX1IW47mhVfzR2yy/i31yPn0oOEhyA3R3dYPs3K6HTd1Eng2rtzbYieVK
zamTkVQmyMG2WFmJBbJ5QoCRkGHR5ZnkJ/4jhZF41GyTTW71dcwOb3ITi9GDsSHv
D5jfUTZy5PXN/91H48SdrVVj6KEziD4h7FnPHpgzpsKJt1wehc83EWR89IEeY/dC
62sNz0s1sMg1BNhoqKesdCSUhjEURGyqGUaF7Ge+0baJAgMBAAGjggOxMIIDrTAJ
BgNVHRMEAjAAMAsGA1UdDwQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNV
HQ4EFgQUMM0hTiEKfr0/Lp85d7KgQlBfNgcwHwYDVR0jBBgwFoAU60I00Jiwq5/0
G2sI98xkLu8OLEUwLAYDVR0RBCUwI4ISYXV0aC5teS1wcm9maWxlLmV1gg1teS1w
cm9maWxlLmV1MIICIQYDVR0gBIICGDCCAhQwggIQBgsrBgEEAYG1NwECAjCCAf8w
LgYIKwYBBQUHAgEWImh0dHA6Ly93d3cuc3RhcnRzc2wuY29tL3BvbGljeS5wZGYw
NAYIKwYBBQUHAgEWKGh0dHA6Ly93d3cuc3RhcnRzc2wuY29tL2ludGVybWVkaWF0
ZS5wZGYwgfcGCCsGAQUFBwICMIHqMCcWIFN0YXJ0Q29tIENlcnRpZmljYXRpb24g
QXV0aG9yaXR5MAMCAQEagb5UaGlzIGNlcnRpZmljYXRlIHdhcyBpc3N1ZWQgYWNj
b3JkaW5nIHRvIHRoZSBDbGFzcyAxIFZhbGlkYXRpb24gcmVxdWlyZW1lbnRzIG9m
IHRoZSBTdGFydENvbSBDQSBwb2xpY3ksIHJlbGlhbmNlIG9ubHkgZm9yIHRoZSBp
bnRlbmRlZCBwdXJwb3NlIGluIGNvbXBsaWFuY2Ugb2YgdGhlIHJlbHlpbmcgcGFy
dHkgb2JsaWdhdGlvbnMuMIGcBggrBgEFBQcCAjCBjzAnFiBTdGFydENvbSBDZXJ0
aWZpY2F0aW9uIEF1dGhvcml0eTADAgECGmRMaWFiaWxpdHkgYW5kIHdhcnJhbnRp
ZXMgYXJlIGxpbWl0ZWQhIFNlZSBzZWN0aW9uICJMZWdhbCBhbmQgTGltaXRhdGlv
bnMiIG9mIHRoZSBTdGFydENvbSBDQSBwb2xpY3kuMDUGA1UdHwQuMCwwKqAooCaG
JGh0dHA6Ly9jcmwuc3RhcnRzc2wuY29tL2NydDEtY3JsLmNybDCBjgYIKwYBBQUH
AQEEgYEwfzA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Auc3RhcnRzc2wuY29tL3N1
Yi9jbGFzczEvc2VydmVyL2NhMEIGCCsGAQUFBzAChjZodHRwOi8vYWlhLnN0YXJ0
c3NsLmNvbS9jZXJ0cy9zdWIuY2xhc3MxLnNlcnZlci5jYS5jcnQwIwYDVR0SBBww
GoYYaHR0cDovL3d3dy5zdGFydHNzbC5jb20vMA0GCSqGSIb3DQEBBQUAA4IBAQBp
JFAAxZ2gzThBLAGITaUqXBLMgauQQkFjK6AwmPXu3XxDpxAsXTM6ce0DpwOjDWXQ
CCvF8pydSUKBIwuGN8BcQaC5qnyHamc62YO5Q+VkHbRcLyCB/zqjsOO2+G75AZf9
Z9PIzHUFTxIO2rWu76K6IT8vIpjiIwfF5r5irPOzjbWTFTCQwbhBCF7XdMPlma6d
UFGtn+/N7Hg5F/TPHdI7z/oJIkTP79h73+H9Nv6OD7DKIMWZBfvwR9vNIxvaLOMW
0uxmn9nSfUiAHli5nhvI6gAk1JJf31sOkWmd66KIQzC4pR+GRjPzdmbZpXCjqbjq
rsXEfOCMHw9T3c5vV5qy
-----END CERTIFICATE-----
"
);
    public function  __construct(array $IDPCertificates = array())
    {
        $this->IDPCertificates =
                array_merge($this->IDPCertificates, $IDPCertificates);
    }

    /**
     * Get the Identity Provider's certificate
     * @param string $IPDDomainName Identity Provider's domain name
     *        (e.g. foafssl.org)
     * @return object requiested x509 certificate content
     *         (or the default IDP's certificate, if the requested is not found)
     */
    public function getIdpCertificate($IDPDomainName)
    {
       return isset($this->IDPCertificates[$IDPDomainName]) ?
               $this->IDPCertificates[$IDPDomainName]
              : $this->IDPCertificates[self::DEFAULT_IDP];
    }
}
?>
