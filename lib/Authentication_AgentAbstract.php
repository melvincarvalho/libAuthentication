<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_AgentAbstract.php
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

require_once("lib/Authentication_Helper.php");

abstract class Authentication_AgentAbstract {

    public $errors   = NULL;
    public $agentURI = NULL;
    public $agentId  = NULL;
    public $agent    = NULL;

    public function __construct($agentURI) {

        $this->setAgent($agentURI);
    }

    public function Authentication_AgentAbstract($agentURI) {

        $this->__construct($agentURI);

    }

    public function getAgent() {
        return $this->agent;
    }

    public function setAgent($agentURI) {

        if (isset($agentURI)) {
            $this->agentURI = $agentURI;

            if (Authentication_Helper::isValidUrl($agentURI)) {
                $this->loadAgent();
                $this->loadErrors();
                if (!isset($this->errors)) {
                    $this->agentId = $this->getAgentId();
                    $this->agent = $this->getAgentProperties();
                }
            }
            else
                $this->errors = "Invalid foaf file supplied";

        }
        else
        {
            $this->errors = "No foaf file supplied";
        }

    }

    abstract function loadAgent();

    abstract function loadErrors();

    abstract function getAgentProperties();

}

?>
