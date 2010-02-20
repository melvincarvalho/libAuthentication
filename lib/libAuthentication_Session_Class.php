<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : libAuthentication_Session_Class.php
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

class libAuthentication_Session_Class {

    public $webid            =  NULL;
    public $is_authenticated = 0;
    public $agent            = NULL;

    public function __construct($is_authenticated = 0, $agent = NULL, $webid = NULL) {
        $authn_session = session_name();

        if (isset($authn_session)) {
            if (session_start()) {
                $this->is_authenticated = (isset($_SESSION['libAuthentication_is_authenticated']))?$_SESSION['libAuthentication_is_authenticated']:$is_authenticated;
                $this->webid = (isset($_SESSION['libAuthentication_webid']))?$_SESSION['libAuthentication_webid']:$webid;
                $this->agent = (isset($_SESSION['libAuthentication_agent']))?$_SESSION['libAuthentication_agent']:$agent;
            }
        }
    }

    public function libAuthentication_FOAFSSL_Class($is_authenticated = 0, $agent = NULL, $webid = NULL) {

        $this->__construct($is_authenticated, $agent, $webid);

    }

    public function set_authenticated_webid($webid, $agent = NULL) {
        if (!is_null($webid)) {
            $authn_session = session_name();

            if (isset($authn_session)) {
                if (session_start()) {
                    $_SESSION['libAuthentication_is_authenticated'] = 1;
                    $_SESSION['libAuthentication_webid'] = $webid;
                    $_SESSION['libAuthentication_agent'] = $agent;
                }
            }
        }
    }

    public function unset_authenticated_webid() {
        $authn_session = session_name();

        if (isset($authn_session)) {
            if (session_start()) {
                $_SESSION['libAuthentication_is_authenticated'] = 0;
                $_SESSION['libAuthentication_webid'] = NULL;
                $_SESSION['libAuthentication_agent'] = NULL;
            }
        }
    }
}

?>
