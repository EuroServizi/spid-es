require_relative "../xml_security_new"
require "time"
require "nokogiri"
require "base64"
require "openssl"
require "digest/sha1"

# Only supports SAML 2.0
module Spid
  module Saml

    class Response
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
      DSIG      = "http://www.w3.org/2000/09/xmldsig#"

      attr_accessor :options, :response, :document, :settings

      def initialize(response, options = {})
        raise ArgumentError.new("Response cannot be nil") if response.nil?
        self.options  = options
        self.response = response
        begin
          self.document = Spid::XMLSecurityNew::SignedDocument.new(Base64.decode64(response))
        rescue REXML::ParseException => e
          if response =~ /</
            self.document = Spid::XMLSecurityNew::SignedDocument.new(response)
          else
            raise e
          end
        end
        
      end

      def is_valid?
        validate
      end

      def validate!
        validate(false)
      end

      # The value of the user identifier as designated by the initialization request response
      def name_id
        @name_id ||= begin
          node = REXML::XPath.first(document, "/saml2p:Response/saml2:Assertion[@ID='#{document.signed_element_id}']/saml2:Subject/saml2:NameID")
          node ||=  REXML::XPath.first(document, "/saml2p:Response[@ID='#{document.signed_element_id}']/saml2:Assertion/saml2:Subject/saml2:NameID")
          node.nil? ? nil : node.text
        end
      end

      # A hash of alle the attributes with the response. Assuming there is only one value for each key
      def attributes
        @attr_statements ||= begin
          result = {}

          stmt_element = REXML::XPath.first(document, "/p:Response/a:Assertion/a:AttributeStatement", { "p" => PROTOCOL, "a" => ASSERTION })
          return {} if stmt_element.nil?

          stmt_element.elements.each do |attr_element|
            name  = attr_element.attributes["Name"]
            value = attr_element.elements.first.text

            result[name] = value
          end

          result.keys.each do |key|
            result[key.intern] = result[key]
          end

          result
        end
      end

      # When this user session should expire at latest
      def session_expires_at
        @expires_at ||= begin
          node = REXML::XPath.first(document, "/p:Response/a:Assertion/a:AuthnStatement", { "p" => PROTOCOL, "a" => ASSERTION })
          parse_time(node, "SessionNotOnOrAfter")
        end
      end
      
      # Checks the status of the response for a "Success" code
      def success?
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.attributes["Value"] == "urn:oasis:names:tc:SAML:2.0:status:Success"
        end
      end

      # Conditions (if any) for the assertion to run
      def conditions
        @conditions ||= begin
          REXML::XPath.first(document, "/p:Response/a:Assertion[@ID='#{document.signed_element_id}']/a:Conditions", { "p" => PROTOCOL, "a" => ASSERTION })
        end
      end

      

      #metodi per ricavare info per tracciatura agid

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:Response/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node ||= REXML::XPath.first(document, "/p:Response/a:Assertion/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      def response_to_id
        node = REXML::XPath.first(document, "/p:Response", { "p" => PROTOCOL })
        return  node.attributes["InResponseTo"]
      end

      def id
        node = REXML::XPath.first(document, "/p:Response", { "p" => PROTOCOL })
        return  node.attributes["ID"]
      end

      def issue_instant
        node = REXML::XPath.first(document, "/p:Response", { "p" => PROTOCOL })
        return  node.attributes["IssueInstant"]
      end

      def assertion_id
        node = REXML::XPath.first(document, "/p:Response/a:Assertion/", { "p" => PROTOCOL, "a" => ASSERTION  })
        return  node.attributes["ID"]
      end

      def assertion_subject
        node = REXML::XPath.first(document, "/p:Response/a:Assertion/a:Subject/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION  })
        return  node.text
      end

      def assertion_subject_name_qualifier
        node = REXML::XPath.first(document, "/p:Response/a:Assertion/a:Subject/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION  })
        return  node.attributes["NameQualifier"]
      end

     



      private

      def validation_error(message)
        raise ValidationError.new(message)
      end

    def validate(soft = true)
        # prime the IdP metadata before the document validation. 
        # The idp_cert needs to be populated before the validate_response_state method
        
        if settings
          Spid::Saml::Metadata.new(settings).get_idp_metadata
        end
          return false if validate_structure(soft) == false
          return false if validate_response_state(soft) == false
          return false if validate_conditions(soft) == false
        
        # Just in case a user needs to toss out the signature validation,
        # I'm adding in an option for it.  (Sometimes canonicalization is a bitch!)
        return true if settings.skip_validation == true
        
        # document.validte populates the idp_cert
        return false if document.validate_document(get_fingerprint, soft) == false
        
        # validate response code
        return false if success? == false  

        return true
    end


      def validate_structure(soft = true)
        Dir.chdir(File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'schemas'))) do
          @schema = Nokogiri::XML::Schema(IO.read('saml20protocol_schema.xsd'))
          @xml = Nokogiri::XML(self.document.to_s)
        end
        if soft
          @schema.validate(@xml).map{ return false }
        else
          @schema.validate(@xml).map{ |error| raise(Exception.new("#{error.message}\n\n#{@xml.to_s}")) }
        end
      end

      def validate_response_state(soft = true)
        if response.empty?
          return soft ? false : validation_error("Blank response")
        end

        if settings.nil?
          return soft ? false : validation_error("No settings on response")
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          return soft ? false : validation_error("No fingerprint or certificate on settings")
        end

        true
      end

      def get_fingerprint
        idp_metadata = Spid::Saml::Metadata.new(settings).get_idp_metadata
        
        if settings.idp_cert
          cert_text = Base64.decode64(settings.idp_cert)
          cert = OpenSSL::X509::Certificate.new(cert_text)
          Digest::SHA2.hexdigest(cert.to_der).upcase.scan(/../).join(":")
        else
          settings.idp_cert_fingerprint
        end
        
      end

      def validate_conditions(soft = true)
        return true if conditions.nil?
        return true if options[:skip_conditions]

        if not_before = parse_time(conditions, "NotBefore")
          if Time.now.utc < not_before
            return soft ? false : validation_error("Current time is earlier than NotBefore condition")
          end
        end

        if not_on_or_after = parse_time(conditions, "NotOnOrAfter")
          if Time.now.utc >= not_on_or_after
            return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
          end
        end

        true
      end

      def parse_time(node, attribute)
        if node && node.attributes[attribute]
          Time.parse(node.attributes[attribute])
        end
      end
    end
  end
end
