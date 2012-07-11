<?php
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_UrlTest.php
// Date       : 25th Feb 2010
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

require_once 'PHPUnit/Framework.php';
require_once dirname(__FILE__).'/../lib/Authentication_URL.php';
/**
 * @author László Török
 */
class Authentication_URLTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function valid_urls_are_accepted()
    {
        $url_string = 'http://foaf.me/myid#me';
        $url = Authentication_URL::parse($url_string);
        
        $this->assertEquals('http',$url->scheme);
        $this->assertEquals('foaf.me',$url->host);
        $this->assertEquals('/myid#me',$url->path);
        
        $url_serizalized = sprintf('%s',$url);
        $this->assertEquals('http://foaf.me:80/myid#me', $url_serizalized);
        $this->assertEquals($url_string, $url->parsedURL);

    }

    /**
     * @test
     */
    public function returns_NULL_for_invalid_urls()
    {
        $this->assertEquals(NULL, Authentication_URL::parse('http:///myid#me') );
        $this->assertEquals(NULL, Authentication_URL::parse('http://./myid#me') );
    }

    /**
     * @test
     */
    public function query_parameters_are_available_as_key_value_pairs()
    {
        $url_string = 'http://foaf-ssl.org/?authreqissuer=http://foaf.me/simpleLogin.php';
        $url = Authentication_URL::parse($url_string);

        $this->assertEquals('http://foaf.me/simpleLogin.php',$url->getQueryParameter('authreqissuer'));
        $this->assertEquals('someDefaultValue',$url->getQueryParameter('unknownKey', 'someDefaultValue'),
                'a default value can be specified if key not found');
    }
}

?>
