<?php
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_HelperTest.php
// Date       : 26th Mar 2010
//
// Copyright (C) 2012 Melvin Carvalho, Akbar Hossain, László Török
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is furnished
// to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// "Everything should be made as simple as possible, but no simpler."
// -- Albert Einstein
//
//-----------------------------------------------------------------------------------------------------------------------------------

require_once 'PHPUnit/Framework.php';
require_once dirname(__FILE__).'/../lib/Authentication_FoafSSLDelegate.php';
/**
 * @author László Török
 */
class Authentication_FoafSSLDelegateTest extends PHPUnit_Framework_TestCase
{
    private $test_idp_URL = 'http://testidp.org/';
    private $test_idp_private_key = '
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBANDiE2+Xi/WnO+s120NiiJhNyIButVu6zxqlVzz0wy2j4kQVUC4Z
RZD80IY+4wIiX2YxKBZKGnd2TtPkcJ/ljkUCAwEAAQJAL151ZeMKHEU2c1qdRKS9
sTxCcc2pVwoAGVzRccNX16tfmCf8FjxuM3WmLdsPxYoHrwb1LFNxiNk1MXrxjH3R
6QIhAPB7edmcjH4bhMaJBztcbNE1VRCEi/bisAwiPPMq9/2nAiEA3lyc5+f6DEIJ
h1y6BWkdVULDSM+jpi1XiV/DevxuijMCIQCAEPGqHsF+4v7Jj+3HAgh9PU6otj2n
Y79nJtCYmvhoHwIgNDePaS4inApN7omp7WdXyhPZhBmulnGDYvEoGJN66d0CIHra
I2SvDkQ5CmrzkW5qPaE2oO7BSqAhRZxiYpZFb5CI
-----END RSA PRIVATE KEY-----
';
    private $testidp_cert = '
-----BEGIN CERTIFICATE-----
MIIB+zCCAaWgAwIBAgIJALRu4UYakrHfMA0GCSqGSIb3DQEBBQUAMDUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMREwDwYDVQQKEwhUZXN0IElEUDAe
Fw0xMDA0MDYyMDMxMDhaFw0xMTA0MDYyMDMxMDhaMDUxCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMREwDwYDVQQKEwhUZXN0IElEUDBcMA0GCSqGSIb3
DQEBAQUAA0sAMEgCQQDooaDm/YzdQLGGz0QbZJ599l0FaPVBpF/xv4SkLCz59V5S
tVo2RwyUZ75klywVKp37pUGpG6OwhHdCWx+qSOY/AgMBAAGjgZcwgZQwHQYDVR0O
BBYEFB84tFBN9GbuJT8Od9sqAP0b+ziiMGUGA1UdIwReMFyAFB84tFBN9GbuJT8O
d9sqAP0b+ziioTmkNzA1MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0
ZTERMA8GA1UEChMIVGVzdCBJRFCCCQC0buFGGpKx3zAMBgNVHRMEBTADAQH/MA0G
CSqGSIb3DQEBBQUAA0EA1eixIxHxZR6aYlkDEsxsd26QrnYW8B4iplkzCSCFInxl
G/YzrI9CJ5hGnjPPzPwQ8u9zREp71KNwVsrn3h+SVg==
-----END CERTIFICATE-----
';
    /** Signed by foafssl-org */
    private $validIdentityResponse =
     'http://foaf.selfip.org/demoprocesslogin.php?
      webid=http%3A%2F%2Ffoaf.me%2Ftl73%23me&
      ts=2010-04-06T10%3A39%3A32-0700&
      sig=khcCt3kMDJ%2FJ9a86aaFmu9DA5PbArxC%2FzhGStW%2BCM9XLVjkDZ4a8zhiM%2Fy33Od
      Fg6OD1pdAowcL57EaDzRO63oc6UF1Km4bGc4%2Fd42N38RXnO4TmcQudeDjta7E46QxWT9%2F7
      LVI0XvuZPqWjZL%2Futw%2FKprFMbsfwMZZvcOOGpUY%3D';

    /**
     * @test
     */
    public function Auth_fails_if_IDP_returns_confirmation_too_late()
    {
        $allowedTimeWindow = 0;
        $auth = new Authentication_FoafSSLDelegate( false, 
                Authentication_SignedURL::parse($this->validIdentityResponse),
                NULL, NULL, NULL, 
                Authentication_FoafSSLDelegate::SIG_ALG_RSA_SHA1,
                $allowedTimeWindow);
        $this->assertEquals(
                Authentication_FoafSSLDelegate::STATUS_IDP_RESPONSE_TIMEOUT_ERR,
                            $auth->authnDiagnostic);
    }
    /**
     * @test
     */
    public function Auth_succesful_if_signed_url_can_be_verified()
    {
        

        $signedUrl = $this->signedUrl();

        $certRepo = new Authentication_X509CertRepo(array(
            $this->test_idp_URL => $this->testidp_cert
        ));
        $referer = new Authentication_URL($this->test_idp_URL);

        $auth = new Authentication_FoafSSLDelegate(
                false, $signedUrl, $referer, $certRepo);

        $this->assertEquals(
                Authentication_FoafSSLDelegate::STATUS_DELEGATED_LOGIN_OK,
                $auth->authnDiagnostic);

        $this->assertEquals(1, $auth->isAuthenticated);
       
    }

    private function signedUrl()
    {
        $now = new DateTime();
        $idpResponseURL =
            'http://foaf.selfip.org/demoprocesslogin.php?
             webid=http://foaf.me/tl73#me&
             ts='.$now->format(DateTime::ISO8601);
        openssl_sign($idpResponseURL, $signature, $this->test_idp_private_key);
        $idpSignedResponseURL= $idpResponseURL.'&sig='.base64_encode($signature);
        echo $idpSignedResponseURL.'\n';
        return Authentication_SignedURL::parse($idpSignedResponseURL);
    }
}

?>
