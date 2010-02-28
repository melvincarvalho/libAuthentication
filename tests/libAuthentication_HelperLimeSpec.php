<?php
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   :libAuthHelperLimeSpec.php
// Date       : 28th Feb 2010
//
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
	require_once 'lime.php';
	require_once dirname(__FILE__).'/../lib/libAuthentication_Helper.php';
	
	// we use a mock function instead of get_headers with predefined expectations
	function ret_http_200_header() {
		return 'HTTP/1.0 200 OK\n';
	}

	$t = new lime_test(2); // number of "planned" assertions
	
	$t->comment('Require that "libAuthentication_Helper::is_valid_url(...)" ...');

        $t->is(libAuthentication_Helper::is_valid_url('',null),false, '...rejects empty URLs');
	
        $t->is(libAuthentication_Helper::is_valid_url(
		'http://foaf.me/index.php?webid=http://foaf.me/laczoka#me',
		'ret_http_200_header'), 
		true, '...accepts well formed URLs that return HTTP 200');
		
	/* some further features */
?>