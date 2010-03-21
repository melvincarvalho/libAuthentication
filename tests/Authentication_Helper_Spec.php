<?php
require_once 'PHPUnit/Framework.php';
require_once dirname(__FILE__).'/../lib/Authentication_Helper.php';

class AuthenticationHelperTest extends PHPUnit_Framework_TestCase
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
          array('23:54:23:af:44','235423AF44','Delimiters are removed' ),
          array('23-54-23-af-44','235423AF44','Delimiters are removed' ),
          array('002354023af44','2354023AF44','Leading zeros are removed' )
        );
    }

    /**
     * @test
     * @dataProvider urls
     */
    public function isValidUrl_verifies_whether_url_is_well_formed_and_resolvable
    (
      $url, $isOk, $comment
    )
    {
        $this->assertEquals($isOk,
                           Authentication_Helper::isValidUrl($url, 'returnsHTTP200'),
                           $comment);
        $this->assertEquals($isOk,
                           Authentication_Helper::isValidUrl($url, 'returnsHTTP301'),
                           $comment);
        $this->assertEquals($isOk,
                           Authentication_Helper::isValidUrl($url, 'returnsHTTP302'),
                           $comment);
        $this->assertEquals(false,
                           Authentication_Helper::isValidUrl($url, 'returnsHTTP404'),
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
            array(array('x' => '0'), array('y' => "1"), array('x'=>'0','y'=>'1'), 'elements of arrays are merged'),
            array(array('x' => '0'), array('x' => "1"), array('x'=>'1'), 'elements of arr2 override elements arr1')
        );
    }

    /**
     * @test
     * @dataProvider arraysToMerge
     */
    public function arrayUnique_removes_duplicate_elements_from_nested_arrays
    (
      $input_arr,$expected_output_arr,$comment
    )
    {
        $this->assertEquals($expected_output_arr, Authentication_Helper::arrayUnique($input_arr),$comment);
    }

    public function arraysWithDuplicateElements()
    {
        return array(
            array(array('x','x'), array('x'),'Remove simple duplicate entries'),
            array(array('x', array('x', 'y')), array('x','y'),'')

        );
    }
}

function returnsHTTP200() { return 'HTTP/1.0 200 OK\n'; }
function returnsHTTP301() { return 'HTTP/1.0 301 OK\n'; }
function returnsHTTP302() { return 'HTTP/1.0 302 OK\n'; }
function returnsHTTP404() { return 'HTTP/1.0 404 OK\n'; }

?>
