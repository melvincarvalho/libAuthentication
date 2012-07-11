<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication.php
// Date       : 21st Mar 2010
//
// See Also   : https://foaf.me/testLibAuthentication.php
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

require_once(dirname(__FILE__)."/Authentication_FoafSSLDelegate.php");
require_once(dirname(__FILE__)."/Authentication_FoafSSLARC.php");
require_once(dirname(__FILE__)."/Authentication_AgentARC.php");


/**
 * Simple weblogin function, assumes config is set
 */
function weblogin() {
     $auth = new Authentication($GLOBALS['config']);
     return $auth;
}

/**
 * Simple weblogin display
 */
function weblogin_display() {
    print '<a id="account" href="https://foafssl.org/srv/idp?authreqissuer=' 
        . "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] 
        . '">Login via foafssl.org</a>';
}


/**
 * Top-level authentication class that integrates multiple authentication
 * procedures. (session, Foaf+SSL, delegated Foaf+SSL)
 */
class Authentication {

    /**
     * After succesful authentication contains the webid
     * @var string
     */
    public  $webid             = NULL;

    public  $isAuthenticated   = 0;

    /**
     * Always contains the diagnostic message for the last authentication attempt
     * @var string
     */
    public  $authnDiagnostic   = NULL;
    
    /**
     *
     * @var array
     */
    public  $agent = NULL;

    private $session = NULL;

    const STATUS_AUTH_VIA_SESSION = "Authenticated via a session";

    public function __construct($ARCConfig, $sig = NULL) {

        // 1. Authenticate via session and return
        $this->session = new Authentication_Session();
        if ($this->session->isAuthenticated) {
            $this->webid           = $this->session->webid;
            $this->isAuthenticated = $this->session->isAuthenticated;
            $this->agent           = $this->session->agent;
            $this->authnDiagnostic = self::STATUS_AUTH_VIA_SESSION;
            return;
        }

        // 2. Authenticate via delegated login
        $sig = isset($sig)?$sig:$_GET["sig"];
        if ( (isset($sig)) ) {
            $authDelegate = new Authentication_FoafSSLDelegate(FALSE);

            $this->webid           = $authDelegate->webid;
            $this->isAuthenticated = $authDelegate->isAuthenticated;
            $this->authnDiagnostic = $authDelegate->authnDiagnostic;
        }

        // 3. Authenticate via native FOAF+SSL
        $authSSL = NULL;
        if ( ($this->isAuthenticated == 0) ) {
            $authSSL = new Authentication_FoafSSLARC($ARCConfig, NULL, FALSE);

            $this->webid           = $authSSL->webid;
            $this->isAuthenticated = $authSSL->isAuthenticated;
            $this->authnDiagnostic = $authSSL->authnDiagnostic;
        }

        if ($this->isAuthenticated) {
            if (isset($authSSL)) {
                $ARCStore = $authSSL->ARCStore;
            } else {
                $ARCStore = NULL;
            }

            $agent = new Authentication_AgentARC($ARCConfig, $this->webid, $ARCStore);
            $this->agent = $agent->getAgent();
        } else {
            $this->webid = NULL;
            $this->agent = NULL;
        }

        if ($this->isAuthenticated) {
            $this->session->setAuthenticatedWebid($this->webid, $this->agent);
        } else {
            $this->session->unsetAuthenticatedWebid();
        }
    }

    /**
     * Is the current user authenticated?
     * @return bool
     */
    public function isAuthenticated() {
        return $this->isAuthenticated;
    }

    /**
     * Leave the authenticated session
     */
    public function logout() {
        $this->isAuthenticated = 0;
        $this->session->unsetAuthenticatedWebid();
    }

    /**
     * Returns an the authenticated user's parsed Foaf profile
     * @return Authentication_AgentARC
     */
    public function getAgent() {
        return $this->agent;
    }
}

?>
