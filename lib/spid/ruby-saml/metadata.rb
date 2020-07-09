require "rexml/document"
require "rexml/xpath"
require "net/https"
require "uri"
require "digest/md5"
require "nokogiri"
require_relative "../xml_security_new" #fa il require della nokogiri

# Class to return SP metadata based on the settings requested.
# Return this XML in a controller, then give that URL to the the 
# IdP administrator.  The IdP will poll the URL and your settings
# will be updated automatically
module Spid
  module Saml
    class Metadata
      include REXML
      include Coding
      # a few symbols for SAML class names
      HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      HTTP_GET = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

      attr_accessor :uuid

      def initialize(settings=nil)
        if settings
          @settings = settings
        end
      end

      def generate(settings)
        #meta_doc = REXML::Document.new
        meta_doc = Spid::XMLSecurityNew::Document.new
        if settings.aggregato
          root = meta_doc.add_element "md:EntityDescriptor", { 
            "xmlns:md"        => "urn:oasis:names:tc:SAML:2.0:metadata",
            "xmlns:xml"       => "http://www.w3.org/XML/1998/namespace",
            "xmlns:spid"        => "https://spid.gov.it/saml-extensions",
          }
        else
          root = meta_doc.add_element "md:EntityDescriptor", { 
            "xmlns:md"        => "urn:oasis:names:tc:SAML:2.0:metadata",
            "xmlns:xml"       => "http://www.w3.org/XML/1998/namespace"
          }
        end
        
        if settings.issuer != nil
          root.attributes["entityID"] = settings.issuer
        end
        #Tolto per non far cambiare sempre il metadata
        #uuid = "_" + UUID.new.generate
        #genero l'id come hash dell'entityID
        uuid = "_"+Digest::MD5.hexdigest(settings.issuer)
        self.uuid = uuid
        root.attributes["ID"] = uuid

        sp_sso = root.add_element "md:SPSSODescriptor", { 
            "protocolSupportEnumeration" => "urn:oasis:names:tc:SAML:2.0:protocol",
            "WantAssertionsSigned"       => "true",
            "AuthnRequestsSigned"         => "true"

        }


        # if settings.sp_cert != nil
        #   keyDescriptor = sp_sso.add_element "md:KeyDescriptor", {
        #     "use" => "signing"
        #   }
        #   keyInfo = keyDescriptor.add_element "ds:KeyInfo", {
        #     "xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#"
        #   }
        #   x509Data = keyInfo.add_element "ds:X509Data"
        #   x509Certificate = x509Data.add_element "ds:X509Certificate"
        #   file = ""
        #   File.foreach(settings.sp_cert){ |line|
        #                                file  += line unless (line.include?("RSA PUBLIC KEY") || line.include?("CERTIFICATE")) 
        #                              }
        #   x509Certificate.text = file                            
        # end

        # Add KeyDescriptor if messages will be signed / encrypted
        #cert = settings.get_sp_cert
        cert = settings.get_cert(settings.sp_cert)
        if cert
          
          if cert.is_a?(String)
            cert = OpenSSL::X509::Certificate.new(cert)
          end
          
          cert_text = Base64.encode64(cert.to_der).to_s.gsub(/\n/, "").gsub(/\t/, "")
          kd = sp_sso.add_element "md:KeyDescriptor", { "use" => "signing" }
          ki = kd.add_element "ds:KeyInfo", {"xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#"}
          xd = ki.add_element "ds:X509Data"
          xc = xd.add_element "ds:X509Certificate"
          xc.text = cert_text

          # kd2 = sp_sso.add_element "md:KeyDescriptor", { "use" => "encryption" }
          # ki2 = kd2.add_element "ds:KeyInfo", {"xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#"}
          # xd2 = ki2.add_element "ds:X509Data"
          # xc2 = xd2.add_element "ds:X509Certificate"
          # xc2.text = cert_text
        end

        if !settings.sp_external_consumer_cert.nil? && settings.sp_external_consumer_cert.length > 0
          settings.sp_external_consumer_cert.each{ |cert_cons_external|
            cert_ex = settings.get_cert(cert_cons_external)
            if cert_ex
              
              if cert_ex.is_a?(String)
                cert_ex = OpenSSL::X509::Certificate.new(cert_ex)
              end
              
              cert_text = Base64.encode64(cert_ex.to_der).to_s.gsub(/\n/, "").gsub(/\t/, "")
              kd = sp_sso.add_element "md:KeyDescriptor", { "use" => "signing" }
              ki = kd.add_element "ds:KeyInfo", {"xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#"}
              xd = ki.add_element "ds:X509Data"
              xc = xd.add_element "ds:X509Certificate"
              xc.text = cert_text
            end
          }
        end

        if settings.single_logout_service_url != nil
          sp_sso.add_element "md:SingleLogoutService", {
              "Binding" => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
              "Location" => settings.single_logout_service_url
          }
          sp_sso.add_element "md:SingleLogoutService", {
              "Binding" => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
              "Location" => settings.single_logout_service_url
          }
        end

        #Logout dei servizi esterni
        unless settings.hash_assertion_consumer.blank?
          settings.hash_assertion_consumer.each_pair{ |index, hash_service|
            unless hash_service['logout'].blank?
              sp_sso.add_element "md:SingleLogoutService", {
                "Binding" => hash_service['logout']['binding'] || "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "Location" => hash_service['logout']['location']
              }
            end
          }
        end

        name_identifier_formats = settings.name_identifier_format
        if name_identifier_formats != nil
          name_id = []
          name_identifier_formats.each_with_index{ |format, index|
            name_id[index] = sp_sso.add_element "md:NameIDFormat"
            name_id[index].text = format
          }
          
        end

        if settings.assertion_consumer_service_url
          
            #ciclo e creo i vari tag AssertionConsumerService
            settings.hash_assertion_consumer.each_pair{ |index, hash_service|

                sp_sso.add_element "md:AssertionConsumerService", {
                  "Binding" => settings.assertion_consumer_service_binding,
                  "Location" => (hash_service['external'] ? hash_service['url_consumer'] : settings.assertion_consumer_service_url ),
                  "isDefault" => hash_service['default'],
                  "index" => index
                }
            }

            # #Caso con eidas
            # sp_sso.add_element "md:AssertionConsumerService", {
            #     "Binding" => settings.assertion_consumer_service_binding,
            #     "Location" => settings.assertion_consumer_service_url,
            #     "index" => 99
            # }
            
            # sp_sso.add_element "md:AssertionConsumerService", {
            #     "Binding" => settings.assertion_consumer_service_binding,
            #     "Location" => settings.assertion_consumer_service_url,
            #     "index" => 100
            # }

            settings.hash_assertion_consumer.each_pair{ |index, hash_service|

              #AttributeConsumingService
              attr_cons_service = sp_sso.add_element "md:AttributeConsumingService", {
                  "index" => index,
              }
              service_name = attr_cons_service.add_element "md:ServiceName", {
                    "xml:lang" => "it"
              }
              service_name.text = hash_service['testo']
              unless hash_service['description'].blank?
                service_description = attr_cons_service.add_element "md:ServiceDescription", {
                  "xml:lang" => "it"
                }
                service_description.text = hash_service['description']
              end
              
              if hash_service['array_campi'].is_a?(Array)
                hash_service['array_campi'].each_with_index{ |attribute, index|
                  attr_cons_service.add_element "md:RequestedAttribute", {
                      "Name" => attribute
                  }
                }
              else #hash
                hash_service['array_campi'].each_pair{ |attribute, name_format|
                  attr_cons_service.add_element "md:RequestedAttribute", {
                      "Name" => attribute,
                      "NameFormat" => name_format
                  }
                }
              end
            }


        end
        #organization
        organization = root.add_element "md:Organization"
        org_name = organization.add_element "md:OrganizationName", {
            "xml:lang" => "it"
        }
        org_name.text = settings.organization['org_name']
        org_display_name = organization.add_element "md:OrganizationDisplayName", {
            "xml:lang" => "it"
        }
    
        org_display_name.text = settings.organization['org_display_name']+(settings.aggregato ? " tramite #{settings.hash_aggregatore['soggetto_aggregatore']}" : '')
        org_url = organization.add_element "md:OrganizationURL", {
            "xml:lang" => "it"
        }
        org_url.text = settings.organization['org_url']

        #ContactPerson per sp aggregato
        if settings.aggregato
          contact_person_aggregatore = root.add_element "md:ContactPerson", {
            "contactType" => "other",
            "spid:entityType" => "spid:aggregator"
          }
          company = contact_person_aggregatore.add_element "md:Company"
          company.text = settings.hash_aggregatore['soggetto_aggregatore']

          extensions_aggregatore = contact_person_aggregatore.add_element "md:Extensions"
          vat_number_aggregatore = extensions_aggregatore.add_element "spid:VATNumber"
          vat_number_aggregatore.text = settings.hash_aggregatore['piva_aggregatore']
          
          ipa_code_aggregatore = extensions_aggregatore.add_element "spid:IPACode"
          ipa_code_aggregatore.text = settings.hash_aggregatore['cipa_aggregatore']

          fiscal_code_aggregatore = extensions_aggregatore.add_element "spid:FiscalCode"
          fiscal_code_aggregatore.text = settings.hash_aggregatore['cf_aggregatore']

          contact_person_aggregato = root.add_element "md:ContactPerson", {
            "contactType" => "other",
            "spid:entityType" => "spid:aggregated"
          }
          company = contact_person_aggregato.add_element "md:Company"
          company.text = settings.organization['org_name']

          extensions_aggregato = contact_person_aggregato.add_element "md:Extensions"
          unless settings.hash_aggregatore['soggetto_aggregato']['vat_number'].blank?
            vat_number_aggregato = extensions_aggregato.add_element "spid:VATNumber"
            vat_number_aggregato.text = settings.hash_aggregatore['soggetto_aggregato']['vat_number']
          end
          unless settings.hash_aggregatore['soggetto_aggregato']['ipa_code'].blank?
            ipa_code_aggregato = extensions_aggregato.add_element "spid:IPACode" 
            ipa_code_aggregato.text = settings.hash_aggregatore['soggetto_aggregato']['ipa_code']
          end
          unless settings.hash_aggregatore['soggetto_aggregato']['fiscal_code'].blank?
            fiscal_code_aggregato = extensions_aggregato.add_element "spid:FiscalCode" 
            fiscal_code_aggregato.text = settings.hash_aggregatore['soggetto_aggregato']['fiscal_code']
          end
        end

        #meta_doc << REXML::XMLDecl.new(version='1.0', encoding='UTF-8')
        meta_doc << REXML::XMLDecl.new("1.0", "UTF-8")

        
        #SE SERVE ANCHE ENCRYPTION
        # # Add KeyDescriptor if messages will be signed / encrypted
        # 
        # if cert
        #   cert_text = Base64.encode64(cert.to_der).gsub("\n", '')
        #   kd = sp_sso.add_element "md:KeyDescriptor", { "use" => "signing" }
        #   ki = kd.add_element "ds:KeyInfo", {"xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#"}
        #   xd = ki.add_element "ds:X509Data"
        #   xc = xd.add_element "ds:X509Certificate"
        #   xc.text = cert_text

        #   kd2 = sp_sso.add_element "md:KeyDescriptor", { "use" => "encryption" }
        #   ki2 = kd2.add_element "ds:KeyInfo", {"xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#"}
        #   xd2 = ki2.add_element "ds:X509Data"
        #   xc2 = xd2.add_element "ds:X509Certificate"
        #   xc2.text = cert_text
        # end

        #cert = settings.get_sp_cert
        cert = settings.get_cert(settings.sp_cert) #inserisco il certificato principale
        # embed signature
        if settings.metadata_signed && settings.sp_private_key && settings.sp_cert
          private_key = settings.get_sp_key
          meta_doc.sign_document(private_key, cert)
        end
        ret = ""
        # stampo come stringa semplice i metadata per non avere problemi con validazione firma
        ret = meta_doc.to_s
        #Logging.debug "Generated metadata:\n#{ret}"

        return ret

      end

      def create_sso_request(message, extra_parameters = {} )
        build_message( :type => "SAMLRequest", 
            :service => "SingleSignOnService", 
            :message => message, :extra_parameters => extra_parameters)
      end
      def create_sso_response(message, extra_parameters = {} )
        build_message( :type => "SAMLResponse", 
            :service => "SingleSignOnService", 
            :message => message, :extra_parameters => extra_parameters)     
      end
      def create_slo_request(message, extra_parameters = {} )
        build_message( :type => "SAMLRequest", 
            :service => "SingleLogoutService", 
            :message => message, :extra_parameters => extra_parameters)
      end
      def create_slo_response(message, extra_parameters = {} )
        build_message( :type => "SAMLResponse", 
            :service => "SingleLogoutService", 
            :message => message, :extra_parameters => extra_parameters)     
      end

      # Construct a SAML message using information in the IdP metadata.  
      # :type can be either "SAMLRequest" or "SAMLResponse" 
      # :service refers to the Binding method, 
      #    either "SingleLogoutService" or "SingleSignOnService"
      # :message is the SAML message itself (XML)  
      # I've provided easy to use wrapper functions above 
      def build_message( options = {} )
        opt = { :type => nil, :service => nil, :message => nil, :extra_parameters => nil }.merge(options)
        url = binding_select( opt[:service] )
        return message_get( opt[:type], url, opt[:message], opt[:extra_parameters] )
      end

      # get the IdP metadata, and select the appropriate SSO binding
      # that we can support.  Currently this is HTTP-Redirect and HTTP-POST
      # but more could be added in the future
      def binding_select(service)
        # first check if we're still using the old hard coded method for 
        # backwards compatability
        if service == "SingleSignOnService" && @settings.idp_sso_target_url != nil
            return @settings.idp_sso_target_url
        end
        if service == "SingleLogoutService" && @settings.idp_slo_target_url != nil
            return  @settings.idp_slo_target_url
        end
        
        meta_doc = get_idp_metadata
        
        return nil unless meta_doc
        # first try GET (REDIRECT)
        sso_element = REXML::XPath.first(meta_doc, "/EntityDescriptor/IDPSSODescriptor/#{service}[@Binding='#{HTTP_GET}']")
        if !sso_element.nil? 
          @URL = sso_element.attributes["Location"]
          Logging.debug "binding_select: GET from #{@URL}"
          return @URL
        end
                
        # next try post
        sso_element = REXML::XPath.first(meta_doc, "/EntityDescriptor/IDPSSODescriptor/#{service}[@Binding='#{HTTP_POST}']")
        if !sso_element.nil? 
          @URL = sso_element.attributes["Location"]
          #Logging.debug "binding_select: POST to #{@URL}"
          return @URL
        end

        # other types we might want to add in the future:  SOAP, Artifact
      end


      def fetch(uri_str, limit = 10)
        # You should choose a better exception.
        raise ArgumentError, 'too many HTTP redirects' if limit == 0

        uri = URI.parse(uri_str)
        if uri.scheme == "http"
          response = Net::HTTP.get_response(uri)
        elsif uri.scheme == "https"
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          # Most IdPs will probably use self signed certs
          #http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          get = Net::HTTP::Get.new(uri.request_uri)
          response = http.request(get)
        end

        case response
        when Net::HTTPSuccess then
          response
        when Net::HTTPRedirection then
          location = response['location']
          warn "redirected to #{location}"
          fetch(location, limit - 1)
        else
          response.value
        end
      end



      # Retrieve the remote IdP metadata from the URL or a cached copy 
      # returns a REXML document of the metadata
      def get_idp_metadata
        return false if @settings.idp_metadata.nil?
      
        # Look up the metdata in cache first
        id = Digest::MD5.hexdigest(@settings.idp_metadata)
        response = fetch(@settings.idp_metadata)
        #meta_text = response.body
        #testo_response = meta_text.sub!(' xmlns:xml="http://www.w3.org/XML/1998/namespace"', '') da errori
        #uso nokogiri per cercare il certificato, uso la funzione che rimuove tutti i namespace 
        doc_noko = Nokogiri::XML(response.body.gsub(/\n/, "").gsub(/\t/, "")) #modifica per poste
        doc_noko.remove_namespaces!
        extract_certificate(doc_noko)
        doc_rexml = REXML::Document.new(doc_noko.to_xml)

        return doc_rexml

        # USE OF CACHE WITH CERTIFICATE
        # lookup = @cache.read(id)
        # if lookup != nil
        #   Logging.debug "IdP metadata cached lookup for #{@settings.idp_metadata}"
        #   doc = REXML::Document.new( lookup )
        #   extract_certificate( doc )
        #   return doc
        # end
        
        # Logging.debug "IdP metadata cache miss on #{@settings.idp_metadata}"
        # # cache miss
        # if File.exists?(@settings.idp_metadata)
        #   fp = File.open( @settings.idp_metadata, "r")
        #   meta_text = fp.read
        # else
        #   uri = URI.parse(@settings.idp_metadata)
        #   if uri.scheme == "http"
        #     response = Net::HTTP.get_response(uri)
        #     meta_text = response.body
        #   elsif uri.scheme == "https"
        #     http = Net::HTTP.new(uri.host, uri.port)
        #     http.use_ssl = true
        #     # Most IdPs will probably use self signed certs
        #     #http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        #     http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        #     get = Net::HTTP::Get.new(uri.request_uri)
        #     response = http.request(get)
        #     meta_text = response.body
        #   end
        # end
        # # Add it to the cache
        # @cache.write(id, meta_text, @settings.idp_metadata_ttl )
        # doc = REXML::Document.new( meta_text )
        # extract_certificate(doc)
        # return doc
      end

      def extract_certificate(meta_doc)
        #ricerco il certificato con nokogiri
        # pull out the x509 tag
        x509 = meta_doc.xpath("//EntityDescriptor//IDPSSODescriptor//KeyDescriptor//KeyInfo//X509Data//X509Certificate")

        #x509 = REXML::XPath.first(meta_doc, "/md:EntityDescriptor/md:IDPSSODescriptor"+"/md:KeyDescriptor"+"/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
        # If the IdP didn't specify the use attribute
        if x509.nil?
          x509 = meta_doc.xpath("//EntityDescriptor//IDPSSODescriptor//KeyDescriptor//KeyInfo//X509Data//X509Certificate")
          # x509 = REXML::XPath.first(meta_doc, 
          #       "/EntityDescriptor/IDPSSODescriptor" +
          #     "/KeyDescriptor" +
          #     "/ds:KeyInfo/ds:X509Data/ds:X509Certificate"
          #   )
        end
        @settings.idp_cert = x509.children.to_s.gsub(/\n/, "").gsub(/\t/, "")
      end

      # construct the parameter list on the URL and return
      def message_get( type, url, message, extra_parameters = {} )
        params = Hash.new
        if extra_parameters
          params.merge!(extra_parameters)
        end
        # compress GET requests to try and stay under that 8KB request limit
        #deflate of samlrequest
        params[type] = encode( deflate( message ) )
        #Logging.debug "#{type}=#{params[type]}"
        
        uri = Addressable::URI.parse(url)
        if uri.query_values == nil
          uri.query_values = params
        else
          # solution to stevenwilkin's parameter merge
          uri.query_values = params.merge(uri.query_values)
        end
        url = uri.to_s
        #Logging.debug "Sending to URL #{url}"
        return url
      end

    end
  end
end
