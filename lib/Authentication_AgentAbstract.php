<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_AgentAbstract.php
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

require_once(dirname(__FILE__)."/Authentication_Helper.php");
/**
 * @author Akbar Hossain
 * @abstract
 * Abstact Foaf parser
 * It takes URI of an user/agent and looks up properties (e.g. public key)
 * of the corresponding Foaf profile.
 */
abstract class Authentication_AgentAbstract {

    /**
     * Contains the error message of the last operation.
     * @var string
     */
    public $errors   = NULL;
    public $agentURI = NULL;
    public $agentId  = NULL;
    private $agent    = NULL;

    public function __construct($agentURI = NULL) {

        $this->setAgent($agentURI);
    }
    /**
     * Returns the parsed agent instance.
     * @return mixed
     */
    public function getAgent() {
        return $this->agent;
    }
    /**
     * Set URI of the agent (that is, the URI of the agent's Foaf profile)
     * @param string $agentURI
     * @return Boolean True if success, False on Error
     */
    public function setAgent($agentURI) {

        if (isset($agentURI)) {
            $this->agentURI = $agentURI;
            $this->errors = NULL;

            if (Authentication_Helper::isValidURL($agentURI)) {
                $this->loadAgent();
                $this->loadErrors();
                if (!isset($this->errors)) {
                    // TODO !!!! Undefined method !!!
                    $this->agentId = $this->getAgentId();
                    $this->agent = $this->getAgentProperties();
                }
            }
            else {
                $this->errors = "Invalid foaf file supplied";
                return(FALSE);
            }
        }
        else
        {
            $this->errors = "No foaf file supplied";
            return FALSE;
        }

        return TRUE;
    }

    protected abstract function loadAgent();

    protected abstract function loadErrors();

    protected abstract function getAgentProperties();

    protected abstract function getAgentId();

}

?>
