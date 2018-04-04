#! /usr/bin/env python3
#coding=utf-8


from OpenSSL import crypto
from OpenSSL.crypto import _lib, _ffi, X509


class Certificate:

    def __init__(self, buff, ftype=crypto.FILETYPE_ASN1):
        self.content = []
        self.ftype = ftype
        self._parse(buff)

    def get(self):
        return self.content

    def _parse(self, buff):
        pycerts = []

        if self.ftype == crypto.FILETYPE_ASN1:
            pkcs7 = crypto.load_pkcs7_data(self.ftype, buff)

            certs_stack = _ffi.NULL
            if pkcs7.type_is_signed():
                certs_stack = pkcs7._pkcs7.d.sign.cert
            elif pkcs7.type_is_signedAndEnveloped():
                certs_stack = pkcs7._pkcs7.d.signed_and_enveloped.cert

            for i in range(_lib.sk_X509_num(certs_stack)):
                tmp = _lib.X509_dup(_lib.sk_X509_value(certs_stack, i))
                pycert = X509._from_raw_x509_ptr(tmp)
                pycerts.append(pycert)
        elif self.ftype == crypto.FILETYPE_PEM:
            pycert = crypto.load_certificate(self.ftype,buff)
            pycerts.append(pycert)

        if not pycerts:
            return None

        def X509Name2dict(o):
            #http://pyopenssl.sourceforge.net/pyOpenSSL.html/openssl-x509name.html
            return dict(countryName=o.countryName,
                stateOrProvinceName=o.stateOrProvinceName,
                localityName=o.localityName,
                organizationName=o.organizationName,
                organizationalUnitName=o.organizationalUnitName,
                commonName=o.commonName,
                emailAddress=o.emailAddress)
        for cert in pycerts:
            self.content.append(
                dict(issuer=X509Name2dict(cert.get_issuer()),
                    serial_number=str(cert.get_serial_number()),
                    subject=X509Name2dict(cert.get_subject()),
                    version=cert.get_version(),
                    md5_digest=cert.digest('md5').decode(),
                    sha1_digest=cert.digest('sha1').decode(),
                    sha256_digest=cert.digest('sha256').decode(),
                    has_expired=cert.has_expired()
                )
            )
