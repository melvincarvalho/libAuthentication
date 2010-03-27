<?php
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_Session_Spec.php
// Date       : 26th Mar 2010
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

require_once 'PHPUnit/Framework.php';
require_once dirname(__FILE__).'/../lib/Authentication_Session.php';

class AuthenticationSessionTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function Authentication_session_persist_Auth_info_to_session_storage()
    {
        $webid = 'http://foaf.me/test#me';

        try {
        $auth_session = new Authentication_Session(1, NULL, 'http://foaf.me/test#me');
        } catch (Exception $e ) {}
        
        $this->assertEquals(1, $_SESSION[Authentication_Session::IS_AUTHENTICATED]);
        $this->assertEquals(NULL, $_SESSION[Authentication_Session::AGENT]);
        $this->assertEquals($webid, $_SESSION[Authentication_Session::WEBID]);
    }
}
?>
