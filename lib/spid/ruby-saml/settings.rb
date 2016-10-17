require "xml_security_new"

module Spid
  module Saml
    class Settings
     
      attr_accessor :sp_name_qualifier, :sp_cert, :sp_private_key, :metadata_signed, :requested_attribute, :organization
      attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :idp_cert, :idp_slo_target_url, :idp_metadata, :idp_metadata_ttl, :idp_name_qualifier
      attr_accessor :assertion_consumer_service_binding, :assertion_consumer_service_url
      attr_accessor :name_identifier_value, :name_identifier_format
      attr_accessor :sessionindex, :issuer, :destination_service_url, :authn_context, :requester_identificator
      attr_accessor :single_logout_service_url, :single_logout_service_binding, :single_logout_destination
      attr_accessor :skip_validation
    
      def initialize(config = {})
        config.each do |k,v|
          acc = "#{k.to_s}=".to_sym
          self.send(acc, v) if self.respond_to? acc
        end

        # Set some sane default values on a few options
        self.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        self.single_logout_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        # Default cache TTL for metadata is 1 day
        self.idp_metadata_ttl = 86400
      end


      def get_fingerprint
        idp_cert_fingerprint || begin
          idp_cert = get_idp_cert
          if idp_cert
            fingerprint_alg = XMLSecurity::BaseDocument.new.algorithm(idp_cert_fingerprint_algorithm).new
            fingerprint_alg.hexdigest(idp_cert.to_der).upcase.scan(/../).join(":")
          end
        end
      end

      # @return [OpenSSL::X509::Certificate|nil] Build the IdP certificate from the settings (previously format it)
      #
      def get_idp_cert
        return nil if idp_cert.nil? || idp_cert.empty?
        #decoded_content = Base64.decode64(File.read(idp_cert))
        #formatted_cert = Spid::Saml::Utils.format_cert(idp_cert)
        OpenSSL::X509::Certificate.new(File.read(idp_cert))
      end

      # def get_sp_cert
      #   return nil if certificate.nil? || certificate.empty?

      #   formatted_cert = OneLogin::RubySaml::Utils.format_cert(certificate)
      #   OpenSSL::X509::Certificate.new(formatted_cert)
      # end

      # @return [OpenSSL::X509::Certificate|nil] Build the SP certificate from the settings (previously format it)
      #
      def get_sp_cert
        return nil if sp_cert.nil? || sp_cert.empty?
        #decoded_content = Base64.decode64(File.read(sp_cert))
        formatted_cert = Spid::Saml::Utils.format_cert(sp_cert)
        OpenSSL::X509::Certificate.new(File.read(sp_cert))
      end

      # @return [OpenSSL::PKey::RSA] Build the SP private from the settings (previously format it)
      #
      def get_sp_key
        return nil if sp_private_key.nil? || sp_private_key.empty?

        #formatted_private_key = Spid::Saml::Utils.format_private_key(sp_private_key)
        OpenSSL::PKey::RSA.new(File.read(sp_private_key))
      end





    end
  end
end
