<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_Session.php
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

class Authentication_Session {

    public $webid            =  NULL;
    public $isAuthenticated = 0;
    public $agent            = NULL;

    public function __construct($isAuthenticated = 0, $agent = NULL, $webid = NULL) {
        $authnSession = session_name();

        if (isset($authnSession)) {
            if (session_start()) {
                $this->isAuthenticated = (isset($_SESSION['Authentication_isAuthenticated']))?$_SESSION['Authentication_isAuthenticated']:$isAuthenticated;
                $this->webid = (isset($_SESSION['Authentication_webid']))?$_SESSION['Authentication_webid']:$webid;
                $this->agent = (isset($_SESSION['Authentication_agent']))?$_SESSION['Authentication_agent']:$agent;
            }
        }
    }

    public function Authentication_Session($isAuthenticated = 0, $agent = NULL, $webid = NULL) {

        $this->__construct($isAuthenticated, $agent, $webid);

    }

    public function setAuthenticatedWebid($webid, $agent = NULL) {
        if (!is_null($webid)) {
            $authnSession = session_name();

            if (isset($authnSession)) {
                if (session_start()) {
                    $_SESSION['Authentication_isAuthenticated'] = 1;
                    $_SESSION['Authentication_webid'] = $webid;
                    $_SESSION['Authentication_agent'] = $agent;
                }
            }
        }
    }

    public function unsetAuthenticatedWebid() {
        $authnSession = session_name();

        if (isset($authnSession)) {
            if (session_start()) {
                $_SESSION['Authentication_isAuthenticated'] = 0;
                $_SESSION['Authentication_webid'] = NULL;
                $_SESSION['Authentication_agent'] = NULL;
            }
        }
    }
}

?>
