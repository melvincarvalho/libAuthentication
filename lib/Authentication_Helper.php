<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_Helper.php
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
require_once dirname(__FILE__).'/Authentication_URL.php';

/**
 * Collection of utility functions
 */
class Authentication_Helper {
    
    /**
     * Function to clean up the supplied hex and convert numbers A-F to uppercase characters eg. a:f => AF
     * @param string $hex the hex string to be sanitized
     * @return string Cleaned hexadecimal value
     */
    public static function cleanHex($hex) {
        
        $hex = eregi_replace("[^a-fA-F0-9]", "", $hex);
        $hex = strtoupper($hex);
        $hex = ltrim($hex, '0');

        return($hex);
    }
    
    /**
     * Function to clean up the supplied hex and convert numbers A-F
     * to uppercase characters eg. a:f => AF
     * @param string $url The URL to be verified
     * @param string $getHeadersFunc The function that gets the HTTP response header for the URL
     * @return bool TRUE, if the URL was succesfully resolved and returned HTTP 200 | 301 | 302
     */
    public static function isValidURL ( $url, $getHeadersFunc = 'get_headers' ) {
        $URL = Authentication_URL::parse($url);

        if ( ! $url ) {
            return false;
        }
        
        if ( ($URL->scheme == 'http') || ($URL->scheme=='https')
          && ($URL->host != gethostbyname($URL->host)) )
        {
            $headers = $getHeadersFunc(sprintf("%s",$url));
            $headers = ( is_array ( $headers ) ) ? implode ( "\n", $headers ) : $headers;
            return ( bool ) preg_match ( '#^HTTP/.*\s+[(200|301|302)]+\s#i', $headers );
        }
        return false;
    }

    /**
     * Function to merge two arrays without thorwing exceptions
     * @param array $a
     * @param array $b
     * @return array Merged array
     */
    public static function safeArrayMerge($a, $b) {
        if ($b) {
            if ($a)
                $a = array_merge($a, $b);
            else
                $a = $b;
        }
        return $a;
    }

    /**
     * This function removes duplicate values from multidimensional arrays
     *
     * Note: This is to amend the standard array_unique() function
     *       to handle nested arrays
     * @param array $myarray
     * @return array Result clean of all duplicate entries
     */
    public static function arrayUnique($myArray) {

        if(!is_array($myArray))
            return $myArray;

        foreach ($myArray as &$myvalue) {
            $myvalue=serialize($myvalue);
        }

        $myArray=array_unique($myArray);
        foreach ($myArray as &$myvalue) {
            $myvalue=unserialize($myvalue);
        }

        $res = NULL;
        foreach ($myArray as $myvalue ) {
            $res = Authentication_Helper::safeArrayMerge($res, array($myvalue));
        }
        
        return $res;
    }
}

?>
