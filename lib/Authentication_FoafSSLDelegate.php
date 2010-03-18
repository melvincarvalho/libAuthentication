<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_FoafSSLDelegate.php
// Date       : 14th Feb 2010
//
// See Also   : https://foaf.me/testLibAuthentication.php
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
require_once("lib/Authentication_Session.php");

class Authentication_FoafSSLDelegate {

    public  $webid             = NULL;
    public  $isAuthenticated   = 0;
    public  $authnDiagnostic   = NULL;
    private $requestURI        = NULL;
    private $referer           = NULL;
    private $ts                = NULL;
    private $allowedTimeWindow = 0;
    private $elapsedTime       = 0;

    public function __construct($createSession = TRUE, $sigAlg = 'rsa-sha1', $idpCertificate = 'foafssl.org-cert.pem', $https = NULL, $serverName = NULL, $serverPort = NULL, $requestURI = NULL, $referer = NULL, $error=NULL, $sig = NULL, $webid = NULL, $ts = NULL, $allowedTimeWindow = 300) {

        if ($createSession) {
            $session = new Authentication_Session();
            if ($session->isAuthenticated) {
                $this->webid = $session->webid;
                $this->isAuthenticated = $session->isAuthenticated;
                $this->authnDiagnostic = "Authenticated via a session";
                return;
            }
        }

        $requestURI = isset($requestURI)?$requestURI:$_SERVER["REQUEST_URI"];
        $https = isset($https)?$https:$_SERVER["HTTPS"];
        $serverName = isset($serverName)?$serverName:$_SERVER["SERVER_NAME"];
        $serverPort = isset($serverPort)?$serverPort:$_SERVER["SERVER_PORT"];
        $referer = isset($referer)?$referer:$_GET["referer"];
        $error = isset($error)?$error:$_GET["error"];
        $sig = isset($sig)?$sig:$_GET["sig"];
        $webid = isset($webid)?$webid:$_GET["webid"];
        $ts = isset($ts)?$ts:$_GET["ts"];

        $this->requestURI        = $requestURI;
        $this->referer           = $referer;
        $this->ts                = $ts;
        $this->webid             = $webid;
        $this->allowedTimeWindow = $allowedTimeWindow;

        $this->elapsedTime = time() - strtotime($ts);

        if (isset($this->referer)) {

		$split  = preg_split('/\//', $this->referer);
                
                $idpCertificate = $split[2] . "-cert.pem";
        }


        if ( ($this->elapsedTime < $this->allowedTimeWindow) && (!isset($error)) ) {

            /* Reconstructs the signed message: the URI except the 'sig' parameter */
            $fullURI = ((isset($https) && ($https == "on")) ? "https" : "http")
                    . "://" . $serverName
                    . ($serverPort != ((isset($https) && ($https == "on")) ? 443 : 80) ? ":".$serverPort : "")
                    . $requestURI;

            $signedInfo = substr($fullURI, 0, -5-strlen(urlencode(isset($sig) ? $sig : NULL)));

            /* Extracts the signature */
            $signature = base64_decode(isset($sig) ? $sig : NULL);

            /* Only rsa-sha1 is supported at the moment. */
            if ($sigAlg == "rsa-sha1") {
                /*
                 * Loads the trusted certificate of the IdP: its public key is used to
                 * verify the integrity of the signed assertion.
                */
                $fp   = fopen($idpCertificate, "r");
                if ($fp != FALSE) {
                    $cert = fread($fp, 8192);
                    fclose($fp);

                    $pubKeyId = openssl_get_publickey($cert);

                    /* Verifies the signature */
                    $verified = openssl_verify($signedInfo, $signature, $pubKeyId);
                    if ($verified == 1) {
                        // The verification was successful.
                        $this->isAuthenticated = 1;
                        $this->authnDiagnostic = "Delegated FOAF Login response has been authenticated";
                    }
                    elseif ($verified == 0) {
                        // The signature didn't match.
                        $this->isAuthenticated = 0;
                        $this->authnDiagnostic = "Signature on response could not be verified";
                    } else {
                        // Error during the verification.
                        $this->isAuthenticated = 0;
                        $this->authnDiagnostic = "Signature on response could not be verified";
                    }

                    openssl_free_key($pubKeyId);
                } else {
                    $this->isAuthenticated = 0;
                    $this->authnDiagnostic = "Could not open the pem file of the signing IdP";
                }

            } else {
                // Unsupported signature algorithm.
                $this->isAuthenticated = 0;
                $this->authnDiagnostic = "Unsupported signature algorithm";
            }
        }
        else {
            $this->isAuthenticated = 0;
            if (isset($error))
                $this->authnDiagnostic = $error;
            else
                $this->authnDiagnostic = "Response from delegate IdP was outside of the allowed time window";
        }

        if ($createSession) {
            if ($this->isAuthenticated)
                $session->setAuthenticatedWebid($this->webid);
            else
                $session->unsetAuthenticatedWebid();
        }
    }

    public function Authentication_FoafSSLDelegate($sigAlg = 'rsa-sha1', $idpCertificate = 'foafssl.org-cert.pem', $https = NULL, $serverName = NULL, $serverPort = NULL, $requestURI = NULL, $referer = NULL, $error = NULL, $sig = NULL, $allowedTimeWindow = 300) {

        $this->__construct($sigAlg, $idpCertificate, $https, $serverName, $serverPort, $requestURI, $referer, $error, $sig, $allowedTimeWindow);

    }

}
?>
