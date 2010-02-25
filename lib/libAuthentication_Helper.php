<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : libAuthentication_Helper.php
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

class libAuthentication_Helper {
    
    public function __construct() {
    }
    
    public function libAuthentication_Helper() {
        
        $this->__construct();
        
    }
    
    /* Function to clean up the supplied hex and convert numbers A-F to uppercase characters eg. a:f => AF */
    function cleanhex($hex) {
        
        $hex = eregi_replace("[^a-fA-F0-9]", "", $hex);
        $hex = strtoupper($hex);
        $hex = ltrim($hex, '0');
        
        return($hex);
        
    }
    
    /* This function checks if the supplied uri is a valid uri */
    function is_valid_url ( $url, $get_headers_func = 'get_headers' ) {
        $url = @parse_url($url);
        
        if ( ! $url ) {
            return false;
        }
        
        $url = array_map('trim', $url);
        $url['port'] = (!isset($url['port'])) ? 80 : (int)$url['port'];
        $path = (isset($url['path'])) ? $url['path'] : '';
        
        if ($path == '') {
            $path = '/';
        }
        
        $path .= ( isset ( $url['query'] ) ) ? "?$url[query]" : '';
        
        if ( isset($url['host']) AND isset($url['scheme']) AND ( ($url['scheme']=='http') OR ($url['scheme']=='https') ) AND ($url['host']!=gethostbyname($url['host'])) ) {
            $headers = $get_headers_func("$url[scheme]://$url[host]:$url[port]$path");
            $headers = ( is_array ( $headers ) ) ? implode ( "\n", $headers ) : $headers;
            return ( bool ) preg_match ( '#^HTTP/.*\s+[(200|301|302)]+\s#i', $headers );
        }
        return false;
    }
    
}

?>
