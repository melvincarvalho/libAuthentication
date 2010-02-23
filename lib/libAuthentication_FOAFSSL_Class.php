<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : libAuthentication_FOAFSSL_Class.php
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

require_once("lib/libAuthentication_Helper_Class.php");
require_once("lib/libAuthentication_Session_Class.php");

abstract class libAuthentication_FOAFSSL_Class {

    private $ssl_client_cert     = NULL;
    public  $cert_modulus        = NULL;
    public  $cert_exponent       = NULL;
    public  $cert_subjectAltName = NULL;
    public  $webid               = NULL;
    public  $is_authenticated    = 0;
    public  $authn_diagnostic    = NULL;

    public function __construct($create_session = TRUE, $ssl_client_cert = NULL) {

        if ($create_session) {
            $session = new libAuthentication_Session_Class();
            if ($session->is_authenticated) {
                $this->webid = $session->webid;
                $this->is_authenticated = $session->is_authenticated;
                $this->authn_diagnostic = "Authenticated via a session";
                return;
            }
        }

        $ssl_client_cert = isset($ssl_client_cert)?$ssl_client_cert:$_SERVER['SSL_CLIENT_CERT'];

        $this->ssl_client_cert = $ssl_client_cert;

        if ($this->ssl_client_cert) {

            $this->openssl_pkey_get_public_hex();
            $this->openssl_get_subjectAltName();
            $this->get_auth();

        } else {

            $this->is_authenticated = 0;
            $this->authn_diagnostic = "No Client Certificate Supplied";

        }

        if ($create_session) {
            if ($this->is_authenticated)
                $session->set_authenticated_webid($this->webid);
            else
                $session->unset_authenticated_webid();
        }
    }

    public function libAuthentication_FOAFSSL_Class($ssl_client_cert = NULL) {

        $this->__construct($ssl_client_cert);

    }

    public function __destruct() {

        //echo "\ndestructing " . get_class($this);

    }

    public function __init() {

    }

    /*  */

    /* Function to return the modulus and exponent of the supplied Client SSL Page */
    protected function openssl_pkey_get_public_hex() {

        if ($this->ssl_client_cert) {

            $pub_key  = openssl_pkey_get_public($this->ssl_client_cert);
            $key_data = openssl_pkey_get_details($pub_key);

            //Remove certificate armour
            $key_len   = strlen($key_data['key']);
            $begin_len = strlen('-----BEGIN PUBLIC KEY----- ');
            $end_len   = strlen(' -----END PUBLIC KEY----- ');

            $rsa_cert = substr($key_data['key'], $begin_len, $key_len - $begin_len - $end_len);

            //TODO: remove openssl dependency
            $rsa_cert_struct = `echo "$rsa_cert" | openssl asn1parse -inform PEM -i`;

            $rsa_cert_fields = split("\n", $rsa_cert_struct);
            $rsakey_offset   = split(":",  $rsa_cert_fields[4]);

            //TODO: remove openssl dependency
            $rsa_key = `echo "$rsa_cert" | openssl asn1parse -inform PEM -i -strparse $rsakey_offset[0]`;

            $rsa_keys = split("\n", $rsa_key);
            $modulus  = split(":", $rsa_keys[1]);
            $exponent = split(":", $rsa_keys[2]);

            $this->cert_modulus  = ltrim($modulus[3],'0');
            $this->cert_exponent = hexdec($exponent[3]);

        }

    }

    /* Returns an array holding the subjectAltName of the supplied SSL Client Certificate */
    protected function openssl_get_subjectAltName() {

        if ($this->ssl_client_cert) {

            $cert = openssl_x509_parse($this->ssl_client_cert);

            if ($cert['extensions']['subjectAltName']) {
                $list          = split("[,]", $cert['extensions']['subjectAltName']);

                for ($i = 0, $i_max = count($list); $i < $i_max; $i++) {

                    if (strcasecmp($list[$i],"")!=0) {

                        $value = split(":", $list[$i], 2);

                        if ($subject_array)
                            $subject_array = array_merge($subject_array, array(trim($value[0]) => trim($value[1])));
                        else
                            $subject_array = array(trim($value[0]) => trim($value[1]));

                    }

                }

                $this->cert_subjectAltName = $subject_array;

            }

        }

    }

    /* Function to compare the certifactes keys against the keys found in the FOAF */
    protected function equal_rsa_keys($foaf_keys) {

        if ( $this->cert_exponent && $this->cert_modulus && $foaf_keys) {

            foreach ($foaf_keys as $foaf_key) {

                if ( ($this->cert_modulus == libAuthentication_Helper_Class::cleanhex($foaf_key['modulus'])) && ($this->cert_exponent == $foaf_key['exponent']) )
                    return TRUE;

            }

            return FALSE;

        }

    }

    abstract protected function get_agent_rsakey();
    // A concrete class must implement this method to return an array of arrays containing the modulus and exponent keys for the referenced $this->webid

    protected function get_auth() {

        if ( ($this->cert_modulus==NULL) || ($this->cert_exponent==NULL) ) {

            $this->is_authenticated = 0;
            $this->authn_diagnostic = 'No RSA Key in the supplied client certificate';

        }
        else {

            $this->cert_webid = $this->cert_subjectAltName['URI'];

            $agent_rsakey = $this->get_agent_rsakey();

            if ($agent_rsakey) {

                if ($this->equal_rsa_keys($agent_rsakey)) {

                    $this->is_authenticated = 1;
                    $this->authn_diagnostic = 'Client Certificate RSAkey matches SAN RSAkey';

                } else {

                    $this->is_authenticated = 0;
                    $this->authn_diagnostic = 'Client Certificate RSAkey does not match SAN RSAkey';

                }

            } else {

                $this->is_authenticated = 0;
                $this->authn_diagnostic = 'No RSAKey found at supplied agent';

            }

        }

    }

}

?>
