<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_Session.php
// Date       : 14th Feb 2010
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
/**
 * Persist authentication information in the session storage
 *
 * @author Akbar Hossain
 */
class Authentication_Session {

    public  $webid            =  NULL;
    public  $isAuthenticated  = 0;
    public  $agent            = NULL;

    private $authnSession     = NULL;

    const IS_AUTHENTICATED = 'Authentication_isAuthenticated';
    const AGENT = 'Authentication_agent';
    const WEBID = 'Authentication_webid';

    /**
     * Created FOAF+SSL authenticated session
     * @param int $isAuthenticated
     * @param mixed $agent
     * @param string $webid
     */
    public function __construct($isAuthenticated = 0, $agent = NULL, $webid = NULL) {
        $this->authnSession = session_name();

        if (isset($this->authnSession)) {
            if (session_start()) {
                $this->isAuthenticated = (isset($_SESSION[self::IS_AUTHENTICATED]))?$_SESSION[self::IS_AUTHENTICATED]:$isAuthenticated;
                $this->webid           = (isset($_SESSION[self::WEBID]))?$_SESSION[self::WEBID]:$webid;
                $this->agent           = (isset($_SESSION[self::AGENT]))?$_SESSION[self::AGENT]:$agent;
            }
        }
    }

    /**
     * Set an authenticated webid
     * @param mixed $webid
     * @param mixed $agent
     */
    public function setAuthenticatedWebid($webid, $agent = NULL) {
        if (!is_null($webid)) {
            $_SESSION[self::IS_AUTHENTICATED] = 1;
            $_SESSION[self::WEBID]            = $webid;
            $_SESSION[self::AGENT]            = $agent;

            $this->isAuthenticated = 1;
            $this->webid           = $webid;
            $this->agent           = $agent;
        }
    }
    /**
     * Unset authenticated webid for current session
     */
    public function unsetAuthenticatedWebid() {
        $_SESSION[self::IS_AUTHENTICATED] = 0;
        $_SESSION[self::AGENT]            = NULL;
        $_SESSION[self::WEBID]            = NULL;

        $this->isAuthenticated = 0;
        $this->webid           = NULL;
        $this->agent           = NULL;
    }
}

?>
