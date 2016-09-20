# SPID Euro Servizi

The Ruby SAML Spid library is a fork of Ruby SAML and it is used for implementing the client side of a SAML authorization, initialization and confirmation requests
with SPID.


## The initialization phase

This is the first request you will get from the identity provider. It will hit your application at a specific URL (that you've announced as being your SAML initialization point). The response to this initialization, is a redirect back to the identity provider, which can look something like this:

```ruby
    def init
        #your login with Spid method..
        #create an instance of Spid::Saml::Authrequest
        request = Spid::Saml::Authrequest.new(get_saml_settings)
        auth_request = request.create
        # Based on the IdP metadata, select the appropriate binding 
        # and return the action to perform to the controller
        meta = Spid::Saml::Metadata.new(get_saml_settings)
        signature = get_signature(auth_request.uuid,auth_request.request,"http://www.w3.org/2000/09/xmldsig#rsa-sha1")
        redirect meta.create_sso_request( auth_request.request, {   :RelayState   => request.uuid,
                                                                  :SigAlg       => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                                                                  :Signature    => signature
                                                              } )
    end

    
    def get_signature(relayState, request, sigAlg)
        #url encode of relayState
        relayState_encoded = escape(relayState)
        
        #deflate and base64 of samlrequest
        deflate_request_B64 = encode(deflate(request))
        
        #url encode of samlrequest
        deflate_request_B64_encoded = escape(deflate_request_B64)
        
        #url encode of sigAlg
        sigAlg_encoded = escape(sigAlg)
        
        querystring="SAMLRequest=#{deflate_request_B64_encoded}&RelayState=#{relayState_encoded}&SigAlg=#{sigAlg_encoded}"
        digest = OpenSSL::Digest::SHA1.new(querystring.strip)  
        pk = OpenSSL::PKey::RSA.new File.read(File.join("path.of.cert.pem"))
        qssigned = pk.sign(digest,querystring.strip)
        Base64.encode64(qssigned).gsub(/\n/, "")
    end 
```


Once you've redirected back to the identity provider, it will ensure that the user has been authorized and redirect back to your application for final consumption, this is can look something like this (the authorize_success and authorize_failure methods are specific to your application):

```ruby
    def consume
        #your assertion_consumer method...
        saml_response = @request.params['SAMLResponse'] 
        if !saml_response.nil? 
          #read the settings
          settings = get_saml_settings
          #create an instance of response
          response = Spid::Saml::Response.new(saml_response)
          response.settings = settings

          #validation of response
          if response.is_valid? 
            authorize_success(response.attributes)
          else
            authorize_failure(response.attributes)
          end
      end
    end  
```

In the above there are a few assumptions in place, one being that the response.name_id is an email address. This is all handled with how you specify the settings that are in play via the saml_settings method. That could be implemented along the lines of this:

```ruby
    def get_saml_settings  
        settings = Spid::Saml::Settings.new
        settings.assertion_consumer_service_url     = ...String, url of your assertion consumer.
        settings.issuer                             = ...String, host of your service provider or metadata url.
        settings.sp_cert                            = ...String, path of your cert.pem.
        settings.single_logout_service_url          = ...String, url of idp logout service'.
        settings.sp_name_qualifier                  = ...String, name qualifier of service processor  (like your metadata url).
        settings.idp_name_qualifier                 = ...String, name qualifier of identity provider (idp metadata).
        settings.name_identifier_format             = ...Array, format names ( ["urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"] ).
        settings.destination_service_url            = ...String, url of proxy for single sign on (in Idp).
        settings.single_logout_destination          = ...String, url of logout request. 
        settings.authn_context                      = ...Array, types of permissions allowed (["urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]).
        settings.requester_identificator            = ...unique id of your service provider domain.
        settings.skip_validation                    = ...Bool, skip validation of assertion or response (false).
        settings.idp_sso_target_url                 = ...String, url of idp sso proxy ("https://federatest.lepida.it/gw/SSOProxy/SAML2").
        settings.idp_metadata                       = ...String, url of idp metadata ("https://federatest.lepida.it/gw/metadata").
        settings
    end  
```



## Service Provider Metadata

To form a trusted pair relationship with the IdP, the SP (you) need to provide metadata XML
to the IdP for various good reasons.  (Caching, certificate lookups, relying party permissions, etc)

The class Onelogin::Saml::Metdata takes care of this by reading the Settings and returning XML.  All
you have to do is add a controller to return the data, then give this URL to the IdP administrator.
The metdata will be polled by the IdP every few minutes, so updating your settings should propagate
to the IdP settings.

```ruby
  class SamlController < ApplicationController
    # ... the rest of your controller definitions ...
    def metadata
      meta = Spid::Saml::Metadata.new
      settings = get_saml_settings
      render :xml => meta.generate(settings)
    end
  end
```

## Note on Patches/Pull Requests

* Fork the project.
* Make your feature addition or bug fix.
* Commit, do not mess with rakefile, version, or history. (if you want to have your own version, that is fine but bump version in a commit by itself I can ignore when I pull)
* Send me a pull request.
