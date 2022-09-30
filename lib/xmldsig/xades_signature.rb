# frozen_string_literal: true

module Xmldsig
  # XAdES BES, SHA256, REC-xml-c14n-20010315 whole doc only
  class XadesSignedDocument
    XADES_SIGNATURE = '<ds:Signature Id="XSIG-Signature-Id-1" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo Id="XSIG-SignedInfo-Id-1">
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference Id="XSIG-Reference-Id-1" URI="">
      <ds:Transforms>
	<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue></ds:DigestValue>
    </ds:Reference>
    <ds:Reference Id="XSIG-Reference-Id-2" Type="http://uri.etsi.org/01903#SignedProperties" URI="#XSIG-SignedProperties-Id-1">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
      <ds:DigestValue></ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue Id="XSIG-SignatureValue-Id-1"></ds:SignatureValue>
  <ds:KeyInfo Id="XSIG-KeyInfo-Id-1">
    <ds:X509Data>
      <ds:X509Certificate>
         <%= @cert.to_s.tr("\r\n", \'\').match(/-----BEGIN CERTIFICATE-----(.+)-----END CERTIFICATE-----/)[1].to_s.encode(xml: :text) %>
     </ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
  <ds:Object Id="XSIG-Object-Id-1">
    <xades:QualifyingProperties Id="XSIG-QualifyingProperties-Id-1" Target="#XSIG-Signature-Id-1" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
      <xades:SignedProperties Id="XSIG-SignedProperties-Id-1">
	<xades:SignedSignatureProperties Id="XSIG-SignedSignatureProperties-Id-1">
	  <xades:SigningTime><%= Time.now.strftime "%Y-%m-%dT%H:%M:%S%:z" %></xades:SigningTime>
	  <xades:SigningCertificate>
	    <xades:Cert>
	      <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
		<ds:DigestValue><%= OpenSSL::Digest::SHA256.new(@cert.to_der).base64digest %></ds:DigestValue>
	      </xades:CertDigest>
	      <xades:IssuerSerial>
		    <ds:X509IssuerName><%= @cert.issuer.to_utf8.encode(xml: :text) %></ds:X509IssuerName>
		    <ds:X509SerialNumber><%= @cert.serial.to_s.encode(xml: :text) %></ds:X509SerialNumber>
	      </xades:IssuerSerial>
	    </xades:Cert>
	  </xades:SigningCertificate>
	</xades:SignedSignatureProperties>
      </xades:SignedProperties>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
'
    attr_reader :unsigned_doc, :signed_doc

    if Gem.loaded_specs.key?('erubi')
      def xades_signature
        eval(Erubi::Engine.new(XADES_SIGNATURE).src)
      end
    else
      def xades_signature
        require 'erb'
        ERB.new(XADES_SIGNATURE).result(binding)
      end
    end

    def initialize(xml)
      @unsigned_doc = xml.is_a?(Nokogiri::XML::Document) ? xml : Nokogiri::XML(xml) { |config| config.strict }

      # ? - pwpw sigillum
      raise 'no declaration of xmlns:ds="http://www.w3.org/2000/09/xmldsig#"' unless @unsigned_doc.namespaces['xmlns:ds'] == 'http://www.w3.org/2000/09/xmldsig#'
    end

    def sign_pem(certificate, private_key, key_password)
      cert = if certificate.is_a?(OpenSSL::X509::Certificate)
               certificate
             elsif certificate.is_a?(String)
               OpenSSL::X509::Certificate.new(certificate)
             else
               raise 'incorretc certificate params'
             end
      key = if private_key.is_a?(OpenSSL::PKey::PKey)
              private_key
            elsif private_key.is_a?(String)
              OpenSSL::PKey::RSA.new(private_key, key_password)
            else
              raise 'incorretc key params'
            end

      sign(cert, key)
    end

    def sign_p12(pkcs12, pkcs12_pass = '')
      p12 = if pkcs12.is_a?(OpenSSL::PKCS12) && pkcs12_pass == ''
              pkcs12
            elsif pkcs12.is_a?(String)
              OpenSSL::PKCS12.new(File.read(pkcs12), pkcs12_pass)
            else
              raise 'incorretc p12 params'
            end
      sign(p12.certificate, p12.key)
    end


    private

    def sign(certificate, private_key)
      @cert = certificate
      txt = xades_signature
      doc = @unsigned_doc.dup
      doc.root.add_child(txt)
      unsigned_document = Xmldsig::SignedDocument.new(doc)
      @signed_doc = unsigned_document.sign(private_key)
    end
  end
end
