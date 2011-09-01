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
");
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
