<?php
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : Authentication_X509CertRepo.php
// Date       : 26th Mar 2010
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
 * An X509Certificate repository
 *
 * @author László Török
 */
class Authentication_X509CertRepo
{
    const DEFAULT_IDP = 'foafssl.org';
    private $idpCertificateDir;

    /**
     * Initialize X509 certificate
     * @param $idpCertificateDir Path to the directory containing idp certificates
     *
     */
    public function __construct($idpCertificateDir = '.')
    {
        $this->idpCertificateDir = $idpCertificateDir;
        
    }
    /**
     * Get the Identity Provider's certificate
     * @param string $idpDomainName Identity Provider's domain name (e.g. foafssl.org)
     * @return object This instance
     */
    public function getIdpCertificate($idpDomainName)
    {
        $certificateContent = NULL;
        $filename = dirname($this->idpCertificateDir).'/'.
                    ($idpDomainName ? $idpDomainName : self::DEFAULT_IDP)
                    .'-cert.pem';
        if (file_exists($filename))
                $certificateContent = file_get_contents(
                          $filename, NULL, NULL, 0, 8192);

        return $certificateContent;
    }
}
?>
