<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : libAuthentication_FOAFSSL_Delegate_Class.php
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
require_once("lib/libAuthentication_Session_Class.php");

class libAuthentication_FOAFSSL_Delegate_Class {

    public  $webid               = NULL;
    public  $is_authenticated    = 0;
    public  $authn_diagnostic    = NULL;
    private $request_uri         = NULL;
    private $ts                  = NULL;
    private $allowed_time_window = 0;
    private $elapsed_time        = 0;

    public function __construct($create_session = TRUE, $sig_alg = 'rsa-sha1', $idp_certificate = 'foafssl.org-cert.pem', $https = NULL, $server_name = NULL, $server_port = NULL, $request_uri = NULL, $sig = NULL, $webid = NULL, $ts = NULL, $allowed_time_window = 300) {

        if ($create_session) {
            $session = new libAuthentication_Session_Class();
            if ($session->is_authenticated) {
                $this->webid = $session->webid;
                $this->is_authenticated = $session->is_authenticated;
                $this->authn_diagnostic = "Authenticated via a session";
                return;
            }
        }

        $request_uri = isset($request_uri)?$request_uri:$_SERVER["REQUEST_URI"];
        $https = isset($https)?$https:$_SERVER["HTTPS"];
        $server_name = isset($http_host)?$http_host:$_SERVER["SERVER_NAME"];
        $server_port = isset($server_port)?$server_port:$_SERVER["SERVER_PORT"];
        $sig = isset($sig)?$sig:$_GET["sig"];
        $webid = isset($webid)?$webid:$_GET["webid"];
        $ts = isset($ts)?$ts:$_GET["ts"];

        $this->request_uri         = $request_uri;
        $this->ts                  = $ts;
        $this->webid               = $webid;
        $this->allowed_time_window = $allowed_time_window;

        $this->elapsed_time = time() - strtotime($ts);

        if ($this->elapsed_time < $this->allowed_time_window) {

            /* Reconstructs the signed message: the URI except the 'sig' parameter */
            $full_uri = ((isset($https) && ($https == "on")) ? "https" : "http")
                    . "://" . $server_name
                    . ($server_port != ((isset($https) && ($https == "on")) ? 443 : 80) ? ":".$server_port : "")
                    . $request_uri;

            $signed_info = substr($full_uri, 0, -5-strlen(urlencode(isset($sig) ? $sig : NULL)));

            /* Extracts the signature */
            $signature = base64_decode(isset($sig) ? $sig : NULL);

            /* Only rsa-sha1 is supported at the moment. */
            if ($sig_alg == "rsa-sha1") {
                /*
                 * Loads the trusted certificate of the IdP: its public key is used to
                 * verify the integrity of the signed assertion.
                */
                $fp   = fopen($idp_certificate, "r");
                if ($fp != FALSE) {
                    $cert = fread($fp, 8192);
                    fclose($fp);

                    $pubkeyid = openssl_get_publickey($cert);

                    /* Verifies the signature */
                    $verified = openssl_verify($signed_info, $signature, $pubkeyid);
                    if ($verified == 1) {
                        // The verification was successful.
                        $this->is_authenticated = 1;
                        $this->authn_diagnostic = "Delegated FOAF+SSL response has been authenticated";
                    }
                    elseif ($verified == 0) {
                        // The signature didn't match.
                        $this->is_authenticated = 0;
                        $this->authn_diagnostic = "Signature on response could not be verified";
                    } else {
                        // Error during the verification.
                        $this->is_authenticated = 0;
                        $this->authn_diagnostic = "Signature on response could not be verified";
                    }

                    openssl_free_key($pubkeyid);
                } else {
                    $this->is_authenticated = 0;
                    $this->authn_diagnostic = "Could not open the pem file of the signing IdP";
                }

            } else {
                // Unsupported signature algorithm.
                $this->is_authenticated = 0;
                $this->authn_diagnostic = "Unsupported signature algorithm";
            }
        }
        else {
            $this->is_authenticated = 0;
            $this->authn_diagnostic = "Response from delegate IdP was outside of the allowed time window";
        }

        if ($create_session) {
            if ($this->is_authenticated)
                $session->set_authenticated_webid($this->webid);
            else
                $session->unset_authenticated_webid();
        }
    }

    public function libAuthentication_ARC_FOAFSSL_Class($sig_alg = 'rsa-sha1', $idp_certificate = 'foafssl.org-cert.pem', $https = NULL, $http_host = NULL, $server_port = NULL, $request_uri = NULL, $sig = NULL, $allowed_time_window = 300) {

        $this->__construct($sig_alg, $idp_certificate, $https, $http_host, $server_port, $request_uri, $sig, $allowed_time_window);

    }

}
?>
