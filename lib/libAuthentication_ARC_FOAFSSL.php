<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : libAuthentication_ARC_FOAFSSL.php
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

require_once("arc/ARC2.php");
require_once("lib/libAuthentication_Helper.php");
require_once("lib/libAuthentication_FOAFSSL.php");

class libAuthentication_ARC_FOAFSSL extends libAuthentication_FOAFSSL
{
   private $ARC_config = NULL;
   private $ARC_store  = NULL;

   public function __construct($ARC_config, $create_session= TRUE, $ssl_client_cert = NULL) {

       $this->ARC_config = $ARC_config;

       parent::__construct($create_session, $ssl_client_cert);
   }

    public function libAuthentication_ARC_FOAFSSL($ARC_config, $create_session = TRUE, $ssl_client_cert = NULL) {

        $this->__construct($ARC_config, $create_session, $ssl_client_cert);

    }

    private function create_store() {

        if (libAuthentication_Helper::is_valid_url($this->cert_webid)) {

            $store = ARC2::getStore($this->ARC_config);

            if (!$store->isSetUp()) {
                $store->setUp();
            }

            $store->reset();

            /* LOAD will call the Web reader, which will call the
               format detector, which in turn triggers the inclusion of an
               appropriate parser, etc. until the triples end up in the store. */
            $store->query('LOAD <'.$this->cert_webid.'>');

            $this->ARC_store = $store;
        }
    }

    /* Returns an array of the modulus and exponent in the supplied RDF */
    protected function get_foaf_rsakey() {

        $modulus = NULL;
        $exponent = NULL;
        $res = NULL;

	/* list names */
        $q = "
		  PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
		  PREFIX rsa: <http://www.w3.org/ns/auth/rsa#>
		  PREFIX cert: <http://www.w3.org/ns/auth/cert#>
		  PREFIX foaf: <http://xmlns.com/foaf/0.1/> .
		  SELECT ?mod ?exp  WHERE {
			?sig cert:identity ?person .
			?sig a rsa:RSAPublicKey;
				rsa:modulus [ cert:hex ?mod ] ;
				rsa:public_exponent [ cert:decimal ?exp ] .
		  FILTER regex(?person, '".$this->cert_webid."')
		  }";

      if ($rows = $this->ARC_store->query($q, 'rows')) {
            foreach ($rows as $row) {
                $modulus =  libAuthentication_Helper::cleanhex($row['mod']);
                $exponent = libAuthentication_Helper::cleanhex($row['exp']);

                $res[] = array( 'modulus'=>$modulus, 'exponent'=>$exponent );
            }
       }
       
       return ( $res );
    }

    protected function get_agent_rsakey() {

        if ($this->cert_webid) {

            $this->create_store();

            $store = $this->ARC_store;

            if (isset($store) && ($errs = $store->getErrors()))
            {
                return NULL;
            }

            if (isset($store) && ($agentrsakey = $this->get_foaf_rsakey()))
                return($agentrsakey);

            return NULL;

        }

    }

}

?>
