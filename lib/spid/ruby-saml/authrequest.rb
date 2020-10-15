require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"
require "rubygems"
require "addressable/uri"

module Spid::Saml
  include REXML
  class Authrequest
    # a few symbols for SAML class names
    HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    HTTP_GET = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    
    attr_accessor :uuid, :request, :issue_instant

    def initialize( settings )
      @settings = settings
      @request_params = Hash.new
    end
    
    def create(params = {})
      uuid = "_" + UUID.new.generate
      self.uuid = uuid
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      self.issue_instant = time
      # Create AuthnRequest root element using REXML 
      request_doc = Spid::XMLSecurityNew::Document.new
      request_doc.context[:attribute_quote] = :quote
      root = request_doc.add_element "saml2p:AuthnRequest", { "xmlns:saml2p" => "urn:oasis:names:tc:SAML:2.0:protocol", 
                                                              "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
                                                             }
      root.attributes['ID'] = uuid
      root.attributes['IssueInstant'] = time
      root.attributes['Version'] = "2.0"
      #root.attributes['ProtocolBinding'] = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      root.attributes['AttributeConsumingServiceIndex'] = @settings.assertion_consumer_service_index
      root.attributes['ForceAuthn'] = "true"
      #root.attributes['IsPassive'] = "false"
      #usato AssertionConsumerServiceURL e ProtocolBinding in alternativa, pag 8 regole tecniche
      root.attributes['AssertionConsumerServiceIndex'] = @settings.attribute_consuming_service_index

      #Tolto, utilizzo AssertionConsumerServiceIndex
      # # Conditionally defined elements based on settings
      # if @settings.assertion_consumer_service_url != nil
      #   root.attributes["AssertionConsumerServiceURL"] = @settings.assertion_consumer_service_url
      # end

      if @settings.destination_service_url != nil
        root.attributes["Destination"] = @settings.destination_service_url
      end

      unless @settings.issuer.blank?
        issuer = root.add_element "saml:Issuer"
        issuer.attributes['NameQualifier'] = ( @settings.aggregato ? @settings.sp_name_qualifier : @settings.issuer )
        issuer.attributes['Format'] = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
        issuer.text = @settings.issuer #questo valore deve essere uguale al #entityID dei metadata che usa @settings.issuer
      end

      #opzionale
      unless @settings.sp_name_qualifier.blank?
        subject = root.add_element "saml:Subject"
        name_id = subject.add_element "saml:NameID"
        name_id.attributes['Format'] = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        name_id.attributes['NameQualifier'] = @settings.sp_name_qualifier
        name_id.text = @settings.sp_name_identifier
      end



      if @settings.name_identifier_format != nil
        root.add_element "saml2p:NameIDPolicy", { 
            # Might want to make AllowCreate a setting?
            #{}"AllowCreate"     => "true",
            "Format"          => @settings.name_identifier_format[0]
        }
      end

      # BUG fix here -- if an authn_context is defined, add the tags with an "exact"
      # match required for authentication to succeed.  If this is not defined, 
      # the IdP will choose default rules for authentication.  (Shibboleth IdP)
      if @settings.authn_context != nil
        requested_context = root.add_element "saml2p:RequestedAuthnContext", { 
          "Comparison" => "minimum"
        }
        context_class = []
        @settings.authn_context.each_with_index{ |context, index|
          context_class[index] = requested_context.add_element "saml:AuthnContextClassRef"
          context_class[index].text = context
        }
        
      end

      if @settings.requester_identificator != nil
        requester_identificator = root.add_element "saml2p:Scoping", { 
          "ProxyCount" => "0"
        }
        identificators = []
        @settings.requester_identificator.each_with_index{ |requester, index|
          identificators[index] = requester_identificator.add_element "saml2p:RequesterID"
          identificators[index].text = requester
        }
        
      end

      request_doc << REXML::XMLDecl.new("1.0", "UTF-8")
      
      #LA FIRMA VA MESSA SOLO NEL CASO CON HTTP POST
      # cert = @settings.get_sp_cert
      #   # embed signature
      #   if @settings.metadata_signed && @settings.sp_private_key && @settings.sp_cert
      #     private_key = @settings.get_sp_key
      #     request_doc.sign_document(private_key, cert)
      #   end

      # stampo come stringa semplice i metadata per non avere problemi con validazione firma
      #ret = request_doc.to_s

      @request = request_doc.to_s

      #Logging.debug "Created AuthnRequest: #{@request}"

      return self

    end
  
    # get the IdP metadata, and select the appropriate SSO binding
    # that we can support.  Currently this is HTTP-Redirect and HTTP-POST
    # but more could be added in the future
    def binding_select
      # first check if we're still using the old hard coded method for 
      # backwards compatability
      if @settings.idp_metadata == nil && @settings.idp_sso_target_url != nil
        @URL = @settings.idp_sso_target_url
        return "GET", content_get
      end
      # grab the metadata
      metadata = Metadata::new
      meta_doc = metadata.get_idp_metadata(@settings)
      
      # first try POST
      sso_element = REXML::XPath.first(meta_doc,
        "/EntityDescriptor/IDPSSODescriptor/SingleSignOnService[@Binding='#{HTTP_POST}']")
      if sso_element 
        @URL = sso_element.attributes["Location"]
        #Logging.debug "binding_select: POST to #{@URL}"
        return "POST", content_post
      end
      
      # next try GET
      sso_element = REXML::XPath.first(meta_doc,
        "/EntityDescriptor/IDPSSODescriptor/SingleSignOnService[@Binding='#{HTTP_GET}']")
      if sso_element 
        @URL = sso_element.attributes["Location"]
        Logging.debug "binding_select: GET from #{@URL}"
        return "GET", content_get
      end
      # other types we might want to add in the future:  SOAP, Artifact
    end
    
    # construct the the parameter list on the URL and return
    def content_get
      # compress GET requests to try and stay under that 8KB request limit
      deflated_request  = Zlib::Deflate.deflate(@request, 9)[2..-5]
      # strict_encode64() isn't available?  sub out the newlines
      @request_params["SAMLRequest"] = Base64.encode64(deflated_request).gsub(/\n/, "")
      
      Logging.debug "SAMLRequest=#{@request_params["SAMLRequest"]}"
      uri = Addressable::URI.parse(@URL)
      if uri.query_values == nil
        uri.query_values = @request_params
      else
        # solution to stevenwilkin's parameter merge
        uri.query_values = @request_params.merge(uri.query_values)
      end
      url = uri.to_s
      #Logging.debug "Sending to URL #{url}"
      return url
    end
    # construct an HTML form (POST) and return the content
    def content_post
      # POST requests seem to bomb out when they're deflated
      # and they probably don't need to be compressed anyway
      @request_params["SAMLRequest"] = Base64.encode64(@request).gsub(/\n/, "")
      
      #Logging.debug "SAMLRequest=#{@request_params["SAMLRequest"]}"
      # kind of a cheesy method of building an HTML, form since we can't rely on Rails too much,
      # and REXML doesn't work well with quote characters
      str = "<html><body onLoad=\"document.getElementById('form').submit();\">\n"
      str += "<form id='form' name='form' method='POST' action=\"#{@URL}\">\n"
      # we could change this in the future to associate a temp auth session ID
      str += "<input name='RelayState' value='ruby-saml' type='hidden' />\n"
      @request_params.each_pair do |key, value|
        str += "<input name=\"#{key}\" value=\"#{value}\" type='hidden' />\n"
        #str += "<input name=\"#{key}\" value=\"#{CGI.escape(value)}\" type='hidden' />\n"
      end
      str += "</form></body></html>\n"
      
      #Logging.debug "Created form:\n#{str}"
      return str
    end
  end
end
