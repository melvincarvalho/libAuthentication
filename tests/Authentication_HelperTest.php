<?php
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_HelperTest.php
// Date       : 26th Mar 2010
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
require_once dirname(__FILE__).'/../lib/Authentication_Helper.php';
/**
 * @author László Török
 */
class Authentication_HelperTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @dataProvider hexadecimalValues
     */
    public function cleanHex_sanitizes_and_extracts_hexadecimal_values
    (
      $taintedHex, $expectedCleanHex, $comment
    )
    {
        $this->assertEquals(
                $expectedCleanHex,
                Authentication_Helper::cleanHex($taintedHex),
                $comment);
    }

    public function hexadecimalValues()
    {
        return array(
          array('345af', '345AF', 'Uppercase conversion'),
          array('23:54:23:af:44','235423AF44','Characters other than 0..9, a..f, A..F are removed' ),
          array('23-54-23-af-44','235423AF44','Characters other than 0..9, a..f, A..F are removed' ),
          array('002354023af44','2354023AF44','Leading zeros are removed' )
        );
    }

    /**
     * @test
     * @dataProvider urls
     */
    public function isValidURL_verifies_whether_url_is_well_formed_and_resolvable
    (
      $url, $isOk, $comment
    )
    {
        $this->assertEquals($isOk,
                           Authentication_Helper::isValidURL($url, 'returnsHTTP200'),
                           $comment);
        $this->assertEquals($isOk,
                           Authentication_Helper::isValidURL($url, 'returnsHTTP301'),
                           $comment);
        $this->assertEquals($isOk,
                           Authentication_Helper::isValidURL($url, 'returnsHTTP302'),
                           $comment);
        $this->assertEquals(false,
                           Authentication_Helper::isValidURL($url, 'returnsHTTP404'),
                           $comment);
    }

    public function urls()
    {
        $ok = true; $not_ok = false;
        return array(
            array('http://foaf.me/', true, 'http scheme is accepted'),
            array('https://foaf.cc/', true, 'https scheme is accepted'),
            array('bzr+ssh://bazaar.canonical.com', false, 'url with scheme other than http or https is rejected'),
            array('foaf.cc', false, 'url with missing scheme is rejected'),
            array('https://foaf.me:8080', true, 'urls with port specification'),
            array('https://foaf.me:8080/', true, 'urls with port specification with trailing "/"'),
            array('http://foaf.me/tl73#me', true, 'urls path and fragment')
        );
    }

    /**
     * @test
     * @dataProvider arraysToMerge
     */
    public function safeArrayMerge_merges_two_arrays_safely($arr1, $arr2, $expectedUnion, $comment)
    {
        $this->assertEquals($expectedUnion,Authentication_Helper::safeArrayMerge($arr1, $arr2),$comment);
    }

    public function arraysToMerge()
    {
        return array(
            array(NULL, array('x'), array('x'),'first array can be null'),
            array(array('x'), NULL, array('x'),'second array can be null'),
            array(array('x' => '0'), array('y' => "1"), array_merge(array('x' => '0'), array('y' => "1")),
                'elements of arrays are merged as with array_merge'),
            array(array('x' => '0'), array('x' => "1"), array_merge(array('x' => '0'), array('x' => "1")),
                'elements of arr2 override elements arr1 as with array_merge')
        );
    }

    /**
     * @test
     */
    public function arrayUnique_removes_duplicate_values_from_multidimensional_arrays()
    {
       // $this->assertEquals(array(array('key' => 0)), Authentication_Helper::arrayUnique(array(array('key'=> 0),array('key'=> 1))), $comment);
    }

    public function arraysWithDuplicateElements()
    {
        return array(
                array('not an array', 'not an array', 'Non-array instances are returned unchanged'),
                array(array(array('key'=> 0),array('key'=> 1)), array(array('key' => 0)),'duplicate keys are removed'),
                array(array(array('key'=> array('nested_key'=> 2)),array('key2'=> array('nested_key'=> 3))),
                        array(array('key' => 0)),'duplicate keys are removed')

            );
    }
}

function returnsHTTP200() { return 'HTTP/1.0 200 OK\n'; }
function returnsHTTP301() { return 'HTTP/1.0 301 OK\n'; }
function returnsHTTP302() { return 'HTTP/1.0 302 OK\n'; }
function returnsHTTP404() { return 'HTTP/1.0 404 OK\n'; }

?>
