# SPID Euro Servizi

La libreria è un fork della libreria Ruby SAML e serve per l'integrazione di un client (Service Provider) con l'autenticazione SPID (Sistema Pubblico di Identità Digitale)
Utilizza lo standard SAML 2 come previsto dalla normativa (Regole tecniche v1. http://www.agid.gov.it/sites/default/files/circolari/spid-regole_tecniche_v1.pdf)


## Fase iniziale

Azione di partenza in cui viene creata la request da inviare all'idp e viene fatto un redirect all'identity provider.

```ruby
    def init
        #creo un istanza di Spid::Saml::Authrequest
        saml_settings = get_saml_settings
        #create an instance of Spid::Saml::Authrequest
        request = Spid::Saml::Authrequest.new(saml_settings)
        auth_request = request.create
        # Based on the IdP metadata, select the appropriate binding 
        # and return the action to perform to the controller
        meta = Spid::Saml::Metadata.new(saml_settings)
        signature = get_signature(auth_request.uuid,auth_request.request,"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        sso_request = meta.create_sso_request( auth_request.request, {  :RelayState   => request.uuid,
                                                                        :SigAlg       => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                                                                        :Signature    => signature } )
        redirect_to sso_request
    end

```
## Generazione della firma

```ruby
    def get_signature(relayState, request, sigAlg)
        #url encode relayState
        relayState_encoded = escape(relayState)
        #deflate e base64 della samlrequest
        deflate_request_B64 = encode(deflate(request))
        #url encode della samlrequest
        deflate_request_B64_encoded = escape(deflate_request_B64)
        #url encode della sigAlg
        sigAlg_encoded = escape(sigAlg)
        querystring="SAMLRequest=#{deflate_request_B64_encoded}&RelayState=#{relayState_encoded}&SigAlg=#{sigAlg_encoded}"
        #puts "**QUERYSTRING** = "+querystring
        digest = OpenSSL::Digest::SHA256.new(querystring.strip) #sha2 a 256
        chiave_privata = xxxxxx  #path della chiave privata con cui firmare 
        pk = OpenSSL::PKey::RSA.new File.read(chiave_privata) #chiave privata
        qssigned = pk.sign(digest,querystring.strip)
        Base64.encode64(qssigned).gsub(/\n/, "")
    end
```


Questo metodo è l'endpoint impostato a livello di metadata del service provider come 'assertion consumer', riceve la response saml con i dati di registrazione fatta su SPID dagli utenti. 

```ruby
    def assertion_consumer
        #id dell' idp che manda response (es: 'infocert','poste')
        provider_id = @request.params['ProviderID']
        #response saml inviata dall'idp
        saml_response = @request.params['SAMLResponse'] 
        if !saml_response.nil? 
            #assegno i settaggi
            settings = get_saml_settings
            #creo un oggetto response
            response = Spid::Saml::Response.new(saml_response)
            #assegno alla response i settaggi
            response.settings = settings
            #estraggo dal Base64 l'xml
            saml_response_dec = Base64.decode64(saml_response)
            #puts "**SAML RESPONSE DECODIFICATA: #{saml_response_dec}"

            #validation of response
            if response.is_valid? 
                attributi_utente = response.attributes
                ...
            else
                #autenticazione fallita!
            end
      end
    end  
```

Questo metodo va a impostare le varie configurazioni che servono per connettersi ad un idp. ( NB: nel caso di SPID ci sono vari idp (Poste, TIM, Info Cert) ) 

```ruby
    def get_saml_settings  
        settings = Spid::Saml::Settings.new
        settings.assertion_consumer_service_url    #= ...String, url dell' assertion consumer al quale arriva la response dell' idp.
        settings.issuer                            #= ...String, host del service provider o url dei metadata.
        settings.sp_cert                           #= ...String, path del certificato pubblico in formato pem.
        settings.sp_private_key                    #= ...String, path della chiave privata in formato pem.
        settings.single_logout_service_url         #= ...String, url del servizio di logout dell'idp.
        settings.sp_name_qualifier                 #= ...String, nome qualificato del service provider o url dei metadata.
        settings.idp_name_qualifier                #= ...String, nome qualificato dell' identity provider o url dei metadata dell' idp.
        settings.name_identifier_format            #= ...Array, formato di nomi ( impostare: ["urn:oasis:names:tc:SAML:2.0:nameid-format:transient"] ).
        settings.destination_service_url           #= ...String, url del servizio per l'identity provider, usato come proxy per il sso.
        settings.single_logout_destination         #= ...String, url di destinazione per la request logout. 
        settings.authn_context                     #= ...Array, tipi di autorizzazioni permesse (impostare: ["urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard", 
                                                                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]).
        settings.requester_identificator           #= ...Array con id dei richiedenti (non usato).
        settings.skip_validation                   #= ...Bool, imposta se evitare la validazione della response o delle asserzioni (false).
        settings.idp_sso_target_url                #= ...String, url target del sso dell' identity provider.
        settings.idp_metadata                      #= ...String, url dei metadata dell' idp.
        settings.requested_attribute               #= ...Array, contiene i nomi dei campi richiesti dal servizio nei metadata.
        settings.metadata_signed                   #= ...String, imposta se firmare i metadata.
        settings.organization                      #= ...Hash, contiene nome breve (org_name), nome esteso (org_display_name) e url (org_url) 
                                                               dell' organizzazione fornitore di servizi.
        settings
    end  
```



## Service Provider Metadata

Per una relazione sicura con l'idp, il Service Provider deve fornire i metadata in formato xml.
La classe Spid::Saml::Metadata legge i settaggi e fornisce l'xml richiesto dagli idp.

```ruby
    def sp_metadata
        settings = get_saml_settings
        meta = Spid::Saml::Metadata.new
        
        @response.headers['Content-Type'] = 'application/samlmetadata+xml'
        $out << meta.generate(settings)
    end
```

