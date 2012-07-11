<?php

//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : config.php                                                                                                  
// Date       : 15th October 2009
// Version    : 0.1
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

$config = array(

        /* db */
        'db_name'        => 'foaf',                     // db name
        'db_user'        => 'root',                          // db username
        'db_pwd'         => '',                              // db password

        /* store */
        'store_name'     => 'arc_tests',                     // tmp table name

        /* modes */
        'multi_user'     => true,                            // not yet impl
        'auto_generate'  => true,                            // not yet impl
        'federation_uri' => '',                              // not yet impl
        'certficate_uri' => 'https://foaf.me/keygen.php'     // not yet impl

);

?>
