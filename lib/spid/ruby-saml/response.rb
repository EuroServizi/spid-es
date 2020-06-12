require_relative "../xml_security_new"
require "time"
require "nokogiri"
require "base64"
require "openssl"
require "digest/sha1"
require_relative "utils"

# Only supports SAML 2.0
module Spid
  module Saml

    class Response
        ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
        PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
        DSIG      = "http://www.w3.org/2000/09/xmldsig#"

        attr_accessor :options, :response, :document, :settings, :attr_name_format
        attr_reader :decrypted_document


        def initialize(response, options = {})
          raise ArgumentError.new("Response cannot be nil") if response.nil?
          self.options  = options
          self.response = response
          if assertion_encrypted?
            @decrypted_document = generate_decrypted_document
          end
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

        # Checks if the SAML Response contains or not an EncryptedAssertion element
        # @return [Boolean] True if the SAML Response contains an EncryptedAssertion element
        #
        def assertion_encrypted?
          false
          #!REXML::XPath.first(self.document, "(/p:Response/EncryptedAssertion/)|(/p:Response/a:EncryptedAssertion/)", { "p" => PROTOCOL, "a" => ASSERTION }).nil?
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
            
            @attr_name_format = []
            stmt_element.elements.each do |attr_element|
              name  = attr_element.attributes["Name"]
              #salvo i vari format per controllare poi che non ce ne siano di null
              @attr_name_format << attr_element.attributes["NameFormat"].blank? ? nil : attr_element.attributes["NameFormat"].text
              value = (attr_element.elements.blank? ? nil : attr_element.elements.first.text)

              result[name] = value
            end
            #mette il symbol
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
            node.attributes["Value"] == "urn:oasis:names:tc:SAML:2.0:status:Success" unless node.blank?
          end
        end

        # Ritorno il valore dello StatusMessage
        def get_status_message
            node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusMessage", { "p" => PROTOCOL, "a" => ASSERTION })
            node.text unless node.blank?
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

        # Gets the Issuers (from Response and Assertion).
        # (returns the first node that matches the supplied xpath from the Response and from the Assertion)
        # @return [Array] Array with the Issuers (REXML::Element)
        #
        def issuers(soft=true)
          @issuers ||= begin
            issuer_response_nodes = REXML::XPath.match(
              document,
              "/p:Response/a:Issuer",
              { "p" => PROTOCOL, "a" => ASSERTION }
            )

            unless issuer_response_nodes.size == 1
              # error_msg = "Issuer of the Response not found or multiple."
              # raise ValidationError.new(error_msg)
              return (soft ? false : validation_error("Issuer of the Response not found or multiple."))
            end

            issuer_assertion_nodes = xpath_from_signed_assertion("/a:Issuer")
            unless issuer_assertion_nodes.size == 1
              # error_msg = "Issuer of the Assertion not found or multiple."
              # raise ValidationError.new(error_msg)
              return (soft ? false : validation_error("Issuer of the Assertion not found or multiple."))
            end

            issuer_response_nodes.each{ |iss|
              #controllo: L'attributo Format di Issuer deve essere presente con il valore urn:oasis:names:tc:SAML:2.0:nameid-format:entity
              return (soft ? false : validation_error("Elemento Issuer non ha formato corretto ")) if !iss.attributes['Format'].nil? && iss.attributes['Format'] != 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'

            }

            issuer_assertion_nodes.each{ |iss|
              #controllo: L'attributo Format di Issuer deve essere presente con il valore urn:oasis:names:tc:SAML:2.0:nameid-format:entity
              return (soft ? false : validation_error("Elemento Issuer non ha formato corretto ")) if iss.attributes['Format'] != 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'

            }

            nodes = issuer_response_nodes + issuer_assertion_nodes

            nodes.map { |node| Utils.element_text(node) }.compact.uniq
          end
        end



        def response_to_id
          node = REXML::XPath.first(document, "/p:Response", { "p" => PROTOCOL })
          return  node.attributes["InResponseTo"] unless node.blank?
        end

        def id
          node = REXML::XPath.first(document, "/p:Response", { "p" => PROTOCOL })
          return  node.attributes["ID"] unless node.blank?
        end

        def issue_instant
          node = REXML::XPath.first(document, "/p:Response", { "p" => PROTOCOL })
          return  node.attributes["IssueInstant"] unless node.blank?
        end

        def assertion_present?
          node = REXML::XPath.first(document, "/p:Response/a:Assertion/", { "p" => PROTOCOL, "a" => ASSERTION  })
          return  !node.blank?
        end

        def assertion_issue_instant
          node = REXML::XPath.first(document, "/p:Response/a:Assertion/", { "p" => PROTOCOL, "a" => ASSERTION  })
          return  node.attributes["IssueInstant"] unless node.blank?
        end

        def assertion_id
          node = REXML::XPath.first(document, "/p:Response/a:Assertion/", { "p" => PROTOCOL, "a" => ASSERTION  })
          return  node.attributes["ID"] unless node.blank?
        end

        def assertion_subject
          node = REXML::XPath.first(document, "/p:Response/a:Assertion/a:Subject/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION  })
          return  node.text
        end

        def assertion_subject_name_qualifier
          node = REXML::XPath.first(document, "/p:Response/a:Assertion/a:Subject/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION  })
          return  node.attributes["NameQualifier"] unless node.blank?
        end

        def assertion_subject_confirmation_data_not_on_or_after
          node_subj_conf_data = xpath_first_from_signed_assertion('/a:Subject/a:SubjectConfirmation/a:SubjectConfirmationData')
          return  node_subj_conf_data.attributes["NotOnOrAfter"] unless node_subj_conf_data.blank?
        end

        def assertion_conditions_not_before
          node_cond_not_before = xpath_first_from_signed_assertion('/a:Conditions')
          return  node_cond_not_before.attributes["NotBefore"] unless node_cond_not_before.blank?
        end

        def assertion_conditions_not_on_or_after
          node_cond_not_on_or_after = xpath_first_from_signed_assertion('/a:Conditions')
          return  node_cond_not_on_or_after.attributes["NotOnOrAfter"] unless node_cond_not_on_or_after.blank?
        end

        private

        def validation_error(message)
          raise ValidationError.new(message)
        end

        def validate(soft = true)
            # prime the IdP metadata before the document validation. 
            # The idp_cert needs to be populated before the validate_response_state method
            
            if settings
              idp_metadata = Spid::Saml::Metadata.new(settings).get_idp_metadata
            end
            
            #carico nei setting l'idp_entity_id  
            entity_descriptor_element = REXML::XPath.first(idp_metadata,"/EntityDescriptor")
            if !entity_descriptor_element.nil? 
              settings.idp_entity_id = entity_descriptor_element.attributes["entityID"]
            end

            return false if validate_structure(soft) == false
            return false if validate_response_state(soft) == false
            return false if validate_conditions(soft) == false
            #validazione assertion firmata
            return false if validate_signed_elements(soft) == false
            #validazione version che sia 2.0
            return false if validate_version(soft) == false
            #validazione version delle asserzioni che sia 2.0
            return false if validate_version_assertion(soft) == false
            #validazione destination
            return false if validate_destination(soft) == false
            #validazione status
            return false if validate_status(soft) == false
            #validazione inresponseto
            return false if validate_presence_inresponseto(soft) == false
            #validazione issuer
            return false if validate_issuer(soft) == false
            #validazioni varie su asserzioni
            return false if validate_assertion(soft) == false
            #validazione presenza format su attributes
            return false if validate_name_format_attributes(soft) == false


            # Just in case a user needs to toss out the signature validation,
            # I'm adding in an option for it.  (Sometimes canonicalization is a bitch!)
            return true if settings.skip_validation == true
            
            # document.validte populates the idp_cert
            return false if document.validate_document(get_fingerprint, soft) == false
            
            # validate response code
            return false if success? == false  

            return true
        end

        # Validates the Issuer (Of the SAML Response and the SAML Assertion)
        # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)
        # @return [Boolean] True if the Issuer matchs the IdP entityId, otherwise False if soft=True
        # @raise [ValidationError] if soft == false and validation fails
        #
        def validate_issuer(soft=true)
          obtained_issuers = issuers(soft)
          if obtained_issuers == false
            return false #errori all'interno del metodo issuers
          else
            obtained_issuers.each do |iss|

              unless Spid::Saml::Utils.uri_match?(iss, settings.idp_entity_id)
                # error_msg = "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>"
                # return append_error(error_msg)
                return (soft ? false : validation_error("Elemento Issuer diverso da EntityID IdP, expected: <#{settings.idp_entity_id}>, but was: <#{iss}>"))
              end
            end

            true
          end
        end

        def validate_presence_inresponseto(soft=true)
          response_to_id_value = response_to_id
          return (soft ? false : validation_error("InResponseTo non specificato o mancante")) if response_to_id_value.blank?
        end



        #validate status e status code
        def validate_status(soft=true)
          #controlli su status
          node_status = REXML::XPath.first(document, "/p:Response/p:Status", { "p" => PROTOCOL, "a" => ASSERTION })
          return (soft ? false : validation_error("Status non presente")) if node_status.blank?
          #controlli su status code
          node_status_code = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          return (soft ? false : validation_error("Status code non presente")) if node_status_code.blank?
          return (soft ? false : validation_error("Status non presente")) unless node_status_code.attributes["Value"] == "urn:oasis:names:tc:SAML:2.0:status:Success"
          true
        end



        # Validates the SAML version (2.0)
        # If fails, the error is added to the errors array.
        # @return [Boolean] True if the SAML Response is 2.0, otherwise returns False
        #
        def version(document)
            @version ||= begin
              node = REXML::XPath.first(
                document,
                "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
                { "p" => PROTOCOL }
              )
              node.nil? ? nil : node.attributes['Version']
            end
        end

        def version_assertion(document)
            assertion_nodes = xpath_from_signed_assertion()
            @version_assertion = "2.0"
            #ciclo sui nodi delle asserzioni, se uno ha una versione diversa da 2.0 ritorno nil
            unless assertion_nodes.blank?
              assertion_nodes.each{ |ass_node|
                return nil if ass_node.attributes['Version'] != "2.0"
              }
            end
            @version_assertion 
        end

        def validate_version(soft = true)
            unless version(self.document) == "2.0"
              #return append_error("Unsupported SAML version")
              return soft ? false : validation_error("Unsupported SAML version")
            end
            true
        end

        def validate_version_assertion(soft = true)
            unless version_assertion(self.document) == "2.0"
              #return append_error("Unsupported SAML version")
              return soft ? false : validation_error("Unsupported SAML Assertion version")
            end
            true
        end

        def validate_signed_elements(soft = true)
            signature_nodes = REXML::XPath.match(decrypted_document.nil? ? document : decrypted_document,"//ds:Signature",{"ds"=>DSIG})
            signed_elements = []
            verified_seis = []
            verified_ids = []
            signature_nodes.each do |signature_node|
              signed_element = signature_node.parent.name
              if signed_element != 'Response' && signed_element != 'Assertion'
                return soft ? false : validation_error("Invalid Signature Element '#{signed_element}'. SAML Response rejected")
                #return append_error("Invalid Signature Element '#{signed_element}'. SAML Response rejected")
              end

              if signature_node.parent.attributes['ID'].nil?
                return soft ? false : validation_error("Signed Element must contain an ID. SAML Response rejected")
                #return append_error("Signed Element must contain an ID. SAML Response rejected")
              end

              id = signature_node.parent.attributes.get_attribute("ID").value
              if verified_ids.include?(id)
                return soft ? false : validation_error("Duplicated ID. SAML Response rejected")
                #return append_error("Duplicated ID. SAML Response rejected")
              end
              verified_ids.push(id)

              # Check that reference URI matches the parent ID and no duplicate References or IDs
              ref = REXML::XPath.first(signature_node, ".//ds:Reference", {"ds"=>DSIG})
              if ref
                uri = ref.attributes.get_attribute("URI")
                if uri && !uri.value.empty?
                  sei = uri.value[1..-1]

                  unless sei == id
                    #return append_error("Found an invalid Signed Element. SAML Response rejected")
                    return soft ? false : validation_error("Found an invalid Signed Element. SAML Response rejected")
                  end

                  if verified_seis.include?(sei)
                    #return append_error("Duplicated Reference URI. SAML Response rejected")
                    return soft ? false : validation_error("Duplicated Reference URI. SAML Response rejected")
                  end

                  verified_seis.push(sei)
                end
              end

              signed_elements << signed_element
            end

            unless signature_nodes.length < 3 && !signed_elements.empty?
              #return append_error("Found an unexpected number of Signature Element. SAML Response rejected")
              return soft ? false : validation_error("Found an unexpected number of Signature Element. SAML Response rejected")
            end

            #if settings.security[:want_assertions_signed] && !(signed_elements.include? "Assertion")
            if !(signed_elements.include? "Assertion")
            #return append_error("The Assertion of the Response is not signed and the SP requires it")
              return soft ? false : validation_error("L'asserzione non è firmata.")
            end

            true
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

        # Validates the Destination, (If the SAML Response is received where expected).
        # If the response was initialized with the :skip_destination option, this validation is skipped,
        # If fails, the error is added to the errors array
        # @return [Boolean] True if there is a Destination element that matches the Consumer Service URL, otherwise False
        
        # @return [String|nil] Destination attribute from the SAML Response.
        #
        def destination
            @destination ||= begin
              node = REXML::XPath.first(
                document,
                "/p:Response",
                { "p" => PROTOCOL }
              )
              node.nil? ? nil : node.attributes['Destination']
            end
        end

        def validate_destination(soft = true)
            return (soft ? false : validation_error("La response non ha destination")) if destination.nil?
            #return true if options[:skip_destination]

            if destination.empty?
              # error_msg = "The response has an empty Destination value"
              # return append_error(error_msg)
              return soft ? false : validation_error("The response has an empty Destination value")
            end

            return true if settings.assertion_consumer_service_url.nil? || settings.assertion_consumer_service_url.empty?

            unless Spid::Saml::Utils.uri_match?(destination, settings.assertion_consumer_service_url)
              # error_msg = "The response was received at #{destination} instead of #{settings.assertion_consumer_service_url}"
              # return append_error(error_msg)
              return soft ? false : validation_error("The response was received at #{destination} instead of #{settings.assertion_consumer_service_url}")
            end

            true
        end

        def validate_assertion(soft = true)
            #posso avere n nodi asserzione..forse
            nodes_assertion = xpath_from_signed_assertion
            unless nodes_assertion.blank?
              #Elemento NameID non specificato
              node_name_id = xpath_first_from_signed_assertion('/a:Subject/a:NameID')
              unless node_name_id.blank?
                return soft ? false : validation_error("Errore su Asserzione: NameID vuoto") if node_name_id.text.blank?
                #controlli su attributo format
                attr_format = node_name_id.attribute("Format")
                return soft ? false : validation_error("Errore su Asserzione: Format su NameID vuoto") if attr_format.blank? || attr_format.to_s != "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" #45
                #controlli su attributo NameQualifier
                attr_name_qual = node_name_id.attribute("NameQualifier")
                return soft ? false : validation_error("Errore su Asserzione: NameQualifier su NameID vuoto") if attr_name_qual.blank? || ( !attr_name_qual.blank? && attr_name_qual.value.blank?)#48 e 49
              else
                return soft ? false : validation_error("Errore su Asserzione: NameID non presente")
                  
              end
              #Controlli su SubjectConfirmation
              node_subj_conf = xpath_first_from_signed_assertion('/a:Subject/a:SubjectConfirmation')
              unless node_subj_conf.blank?
                #controlli su attributo Method
                attr_method = node_subj_conf.attribute("Method")
                return soft ? false : validation_error("Errore su Asserzione: Method su SubjectConfirmation vuoto") if attr_method.blank? || attr_method.to_s != "urn:oasis:names:tc:SAML:2.0:cm:bearer" #53 54 e 55
                #Controlli su SubjectConfirmationData
                node_subj_conf_data = xpath_first_from_signed_assertion('/a:Subject/a:SubjectConfirmation/a:SubjectConfirmationData')
                unless node_subj_conf_data.blank?
                  #controllo attr Recipient, vuoto o diverso da AssertionConsumerServiceURL
                  attr_recipient = node_subj_conf_data.attribute("Recipient")
                  return soft ? false : validation_error("Errore su Asserzione: Recipient su SubjectConfirmationData vuoto o diverso da AssertionConsumerServiceURL") if attr_recipient.blank? || attr_recipient.to_s != settings.assertion_consumer_service_url #57 58 e 59
                  #controllo attr InResponseTo, vuoto o diverso da ID request
                  node_response = REXML::XPath.first(document, "/p:Response", { "p" => PROTOCOL})
                  id_request = node_response.attribute("InResponseTo")
                  attr_in_resp_to = node_subj_conf_data.attribute("InResponseTo")
                  return soft ? false : validation_error("Errore su Asserzione: InResponseTo su SubjectConfirmationData vuoto o diverso da ID request") if attr_in_resp_to.blank? || attr_in_resp_to.to_s != id_request.to_s #57 58 e 59
                
                  #controllo attr NotOnOrAfter se vuoto o non presente  #63 64 
                  attr_not_on_or_after = node_subj_conf_data.attribute("NotOnOrAfter")
                  return soft ? false : validation_error("Errore su Asserzione: NotOnOrAfter su SubjectConfirmationData mancante") if attr_not_on_or_after.blank?


                else
                  return soft ? false : validation_error("Errore su Asserzione: SubjectConfirmationData non presente")
                end

              else
                  return soft ? false : validation_error("Errore su Asserzione: SubjectConfirmation non presente")
              end

              #Controlli su Conditions
              node_conditions = xpath_first_from_signed_assertion('/a:Conditions')
              unless node_conditions.blank?
                  attr_not_before = node_conditions.attribute("NotBefore")
                  return soft ? false : validation_error("Errore su Asserzione: Recipient su SubjectConfirmationData vuoto") if attr_not_before.blank? #75 76
                  #83 84. Assertion - Elemento AudienceRestriction di Condition mancante
                  node_conditions_audience_restrictions = xpath_first_from_signed_assertion('/a:Conditions/a:AudienceRestriction')
                  return soft ? false : validation_error("Errore su Asserzione: AudienceRestriction su Conditions vuoto") if node_conditions_audience_restrictions.blank? #83 84
                  #85 86 87. Assertion - Elemento Audience di AudienceRestriction mancante
                  node_conditions_audience_restrictions_audience = xpath_first_from_signed_assertion('/a:Conditions/a:AudienceRestriction/a:Audience')
                  #Spider.logger.error "\n\n node_conditions_audience_restrictions_audience #{node_conditions_audience_restrictions_audience}"
                  #Spider.logger.error "\n\n settings.issuer #{settings.issuer}"
                  return soft ? false : validation_error("Errore su Asserzione: Audience su AudienceRestriction  vuoto") if node_conditions_audience_restrictions_audience.blank? || node_conditions_audience_restrictions_audience.text != settings.issuer  #83 84
              else
                  return soft ? false : validation_error("Errore su Asserzione: Conditions non presente")
              end

              
              node_auth_stat_context_class_ref = xpath_first_from_signed_assertion('/a:AuthnStatement/a:AuthnContext/a:AuthnContextClassRef')
              #Spider.logger.error "\n\n node_auth_stat_context_class_ref #{node_auth_stat_context_class_ref.text}"
              return soft ? false : validation_error("Errore su Asserzione: AuthnContextClassRef di AuthnContext su AuthnStatement vuoto o non L2") if node_auth_stat_context_class_ref.blank? || ( (node_auth_stat_context_class_ref.text != 'https://www.spid.gov.it/SpidL2') && (node_auth_stat_context_class_ref.text != 'https://www.spid.gov.it/SpidL3')) 
              
              node_attr_stmt_attribute_value = xpath_first_from_signed_assertion("/a:AttributeStatement/a:Attribute/a:AttributeValue")
              #Elemento AttributeStatement presente, ma sottoelemento Attribute non specificato, caso 99
              return soft ? false : validation_error("Errore su Asserzione: AttributeValue di Attribute su AttributeStatement vuoto") if node_attr_stmt_attribute_value.blank?
              

              else
                return soft ? false : validation_error("Errore su Asserzione: non presente")
            end
            true
        end          


        def validate_name_format_attributes(soft=true)
            unless attributes.blank?
                return false if @attr_name_format.blank? || (@attr_name_format.length != (attributes.length / 2))
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

        # Extracts all the appearances that matchs the subelt (pattern)
        # Search on any Assertion that is signed, or has a Response parent signed
        # @param subelt [String] The XPath pattern
        # @return [Array of REXML::Element] Return all matches
        #
        def xpath_from_signed_assertion(subelt=nil)
          doc = decrypted_document.nil? ? document : decrypted_document
          node = REXML::XPath.match(
              doc,
              "/p:Response/a:Assertion[@ID=$id]#{subelt}",
              { "p" => PROTOCOL, "a" => ASSERTION },
              { 'id' => doc.signed_element_id }
          )
          node.concat( REXML::XPath.match(
              doc,
              "/p:Response[@ID=$id]/a:Assertion#{subelt}",
              { "p" => PROTOCOL, "a" => ASSERTION },
              { 'id' => doc.signed_element_id }
          ))
        end

        # Extracts the first appearance that matchs the subelt (pattern)
        # Search on any Assertion that is signed, or has a Response parent signed
        # @param subelt [String] The XPath pattern
        # @return [REXML::Element | nil] If any matches, return the Element
        #
        def xpath_first_from_signed_assertion(subelt=nil)
          doc = decrypted_document.nil? ? document : decrypted_document
          node = REXML::XPath.first(
              doc,
              "/p:Response/a:Assertion[@ID=$id]#{subelt}",
              { "p" => PROTOCOL, "a" => ASSERTION },
              { 'id' => doc.signed_element_id }
          )
          node ||= REXML::XPath.first(
              doc,
              "/p:Response[@ID=$id]/a:Assertion#{subelt}",
              { "p" => PROTOCOL, "a" => ASSERTION },
              { 'id' => doc.signed_element_id }
          )
          node
        end


    end #chiudo classe

  end
end
