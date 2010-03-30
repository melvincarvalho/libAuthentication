<?php
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_Url.php
// Date       : 26th Feb 2010
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

/**
 * Represents a valid Uniform Resource Locator
 *
 * @author László Török
 */
class Authentication_Url
{
    public $scheme;
    public $host;
    public $port;
    public $path;
    public $parsedUrl;
    private $query = array();

    /**
     *
     * @param string $url_string String to parse
     * @return Authentication_Url A valid Authentication_Url instance (or NULL on error)
     */
    public static function parse($url_string)
    {
        $Url = new Authentication_Url();
        $isOk = $Url->parseInternal($url_string);
        return $isOk ? $Url : NULL;
    }
    public function getQueryParameter($key,$default = NULL)
    {
        return isset($this->query[$key]) ? $this->query[$key] : $default;
    }

    public function __toString()
    {
        return $this->scheme.'://'.$this->host.':'.$this->port.$this->path;
    }
    protected function parseInternal($url_string)
    {
        $url_map = @parse_url($url_string);

        if ( !$url_map
          || !$url_map['host']
                // some minimalistic sanitization
          || !preg_match('/[a-zA-Z0-9._-]*[a-zA-Z0-9]$/', $url_map['host']) )
        {
            return false;
        }
        $url_map = array_map('trim', $url_map);

        $this->parsedUrl = $url_string;
        $this->scheme = isset($url_map['scheme']) ? $url_map['scheme'] : 'http' ;
        $this->host = $url_map['host'];
        $this->port = isset($url_map['port']) ? (int)$url_map['port'] : 80;
        $this->path = isset($url_map['path']) ? $url_map['path'] : '';
        parse_str($url_map['query'],$this->query);
        if (!$this->query)
                $this->query = array();

        if ($this->path == '') {
            $this->path = '/';
        }

        $this->path .= isset ( $url_map['query'] ) ? "?$url_map[query]" : '';
        if (isset($url_map['fragment']))
            $this->path .= '#'.$url_map['fragment'];
        
        return true;
    }
}

class Authentication_SignedUrl extends Authentication_Url
{
    public function digitalSignature()
    {
        return base64_decode($this->getQueryParameter('sig'));
    }
    public function urlWithoutSignature()
    {
        $sig = $this->getQueryParameter('sig');
        return substr($this->parsedUrl, 0, -5-strlen(urlencode(isset($sig) ? $sig : NULL)));
    }
    public static function parse($url_string)
    {
        $Url = new Authentication_SignedUrl();
        $isOk = $Url->parseInternal($url_string);
        return $isOk ? $Url : NULL;
    }
}

?>
