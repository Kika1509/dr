# KMS Release Notes

## v0.5.0
- Major upgrade of libs (mainly upgrade to spring-boot 2.0)
    - change of property name that targets KAAS server, new property example is following:


    kms.spring.security.oauth2.client.provider.kms.jwk-set-uri=http://148.198.187.165:5227/kaas/oauth2/keys
    
- Monitoring configuration and setup

- TrK implementation - trk is not enabled by default, configuration will be documented in configuration manual

- Changes in XML generation from KMS schema 
    - needs drop and recreation of KMS database

- KMS-cli implementation

- Consolidation (fixes and improvements) of KMS REST-API

