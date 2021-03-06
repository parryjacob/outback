package outback

import (
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/parryjacob/saml"
)

// OutbackAssertionMaker produces a SAML assertion for the
// given request and assigns it to req.Assertion.
type OutbackAssertionMaker struct {
	oa *OutbackApp
}

// MakeAssertion implements AssertionMaker. It produces a SAML assertion from the
// given request and assigns it to req.Assertion.
func (oam *OutbackAssertionMaker) MakeAssertion(req *saml.IdpAuthnRequest, session *saml.Session) error {
	attributes := []saml.Attribute{}

	oaSession, err := LoadSessionByID(session.ID, oam.oa)
	if err != nil {
		log.WithError(err).Error("Failed to get OutbackSession from saml.Session!")
		return err
	}

	// load attributes from plugins
	for pluginName, pluginFunc := range oam.oa.pluginManager.AttributePlugins {
		attrs, err := pluginFunc(oaSession.ldapUser, req.ServiceProviderMetadata)
		if err != nil {
			log.WithError(err).Errorf("Failed to call AlterAttributes on plugin %s", pluginName)
		} else {
			attributes = append(attributes, attrs...)
		}
	}

	var attributeConsumingService *saml.AttributeConsumingService
	for _, acs := range req.SPSSODescriptor.AttributeConsumingServices {
		if acs.IsDefault != nil && *acs.IsDefault {
			attributeConsumingService = &acs
			break
		}
	}
	if attributeConsumingService == nil {
		for _, acs := range req.SPSSODescriptor.AttributeConsumingServices {
			attributeConsumingService = &acs
			break
		}
	}
	if attributeConsumingService == nil {
		attributeConsumingService = &saml.AttributeConsumingService{}
	}

	for _, requestedAttribute := range attributeConsumingService.RequestedAttributes {
		if requestedAttribute.NameFormat == "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" || requestedAttribute.NameFormat == "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" {
			attrName := requestedAttribute.Name
			attrName = regexp.MustCompile("[^A-Za-z0-9]+").ReplaceAllString(attrName, "")
			switch attrName {
			case "email", "emailaddress":
				attributes = append(attributes, saml.Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []saml.AttributeValue{{
						Type:  "xs:string",
						Value: session.UserEmail,
					}},
				})
			case "name", "fullname", "cn", "commonname":
				attributes = append(attributes, saml.Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []saml.AttributeValue{{
						Type:  "xs:string",
						Value: session.UserCommonName,
					}},
				})
			case "givenname", "firstname":
				attributes = append(attributes, saml.Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []saml.AttributeValue{{
						Type:  "xs:string",
						Value: session.UserGivenName,
					}},
				})
			case "surname", "lastname", "familyname":
				attributes = append(attributes, saml.Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []saml.AttributeValue{{
						Type:  "xs:string",
						Value: session.UserSurname,
					}},
				})
			case "uid", "user", "userid":
				attributes = append(attributes, saml.Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []saml.AttributeValue{{
						Type:  "xs:string",
						Value: session.UserName,
					}},
				})
			}
		}
	}

	if session.UserName != "" {
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "uid",
			Name:         "urn:oid:0.9.2342.19200300.100.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []saml.AttributeValue{{
				Type:  "xs:string",
				Value: session.UserName,
			}},
		})
	}

	if session.UserEmail != "" {
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "eduPersonPrincipalName",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []saml.AttributeValue{{
				Type:  "xs:string",
				Value: session.UserEmail,
			}},
		})
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "mail",
			Name:         "urn:oid:1.3.6.1.4.1.1466.115.121.1.26",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []saml.AttributeValue{{
				Type:  "xs:string",
				Value: session.UserEmail,
			}},
		})
	}
	if session.UserSurname != "" {
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "sn",
			Name:         "urn:oid:2.5.4.4",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []saml.AttributeValue{{
				Type:  "xs:string",
				Value: session.UserSurname,
			}},
		})
	}
	if session.UserGivenName != "" {
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "givenName",
			Name:         "urn:oid:2.5.4.42",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []saml.AttributeValue{{
				Type:  "xs:string",
				Value: session.UserGivenName,
			}},
		})
	}

	if session.UserCommonName != "" {
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "cn",
			Name:         "urn:oid:2.5.4.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []saml.AttributeValue{{
				Type:  "xs:string",
				Value: session.UserCommonName,
			}},
		})
	}

	if len(session.Groups) != 0 {
		groupMemberAttributeValues := []saml.AttributeValue{}
		for _, group := range session.Groups {
			groupMemberAttributeValues = append(groupMemberAttributeValues, saml.AttributeValue{
				Type:  "xs:string",
				Value: group,
			})
		}
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "eduPersonAffiliation",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       groupMemberAttributeValues,
		})
	}

	// Find the desired NameID and format
	nameIDFormat := "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	if len(req.SPSSODescriptor.NameIDFormats) > 0 {
		nameIDFormat = string(req.SPSSODescriptor.NameIDFormats[0])
	}
	nameID := session.NameID
	if nameIDFormat == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" && len(session.UserEmail) > 0 {
		nameID = session.UserEmail
	}

	audienceRestrictions := []saml.AudienceRestriction{
		saml.AudienceRestriction{
			Audience: saml.Audience{Value: req.ServiceProviderMetadata.EntityID},
		},
	}
	if req.ServiceProviderMetadata.EntityID != req.ACSEndpoint.Location {
		audienceRestrictions = append(audienceRestrictions, saml.AudienceRestriction{
			Audience: saml.Audience{Value: req.ACSEndpoint.Location},
		})
	}

	remoteAddr := oam.oa.remoteAddr(req.HTTPRequest).String()

	req.Assertion = &saml.Assertion{
		ID:           newSessionID(),
		IssueInstant: saml.TimeNow(),
		Version:      "2.0",
		Issuer: saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.Metadata().EntityID,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format:          nameIDFormat,
				NameQualifier:   req.IDP.Metadata().EntityID,
				SPNameQualifier: req.ServiceProviderMetadata.EntityID,
				Value:           nameID,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				saml.SubjectConfirmation{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						Address:      remoteAddr,
						InResponseTo: req.Request.ID,
						NotOnOrAfter: saml.TimeNow().Add(saml.MaxIssueDelay),
						Recipient:    req.ACSEndpoint.Location,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:            saml.TimeNow().Add(saml.MaxIssueDelay * -1 / 2),
			NotOnOrAfter:         saml.TimeNow().Add(saml.MaxIssueDelay),
			AudienceRestrictions: audienceRestrictions,
		},
		AuthnStatements: []saml.AuthnStatement{
			saml.AuthnStatement{
				AuthnInstant: session.CreateTime.UTC(),
				SessionIndex: session.Index,
				SubjectLocality: &saml.SubjectLocality{
					Address: remoteAddr,
				},
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			saml.AttributeStatement{
				Attributes: attributes,
			},
		},
	}

	for pgName, fnc := range oam.oa.pluginManager.AssertionPlugins {
		if err := fnc(oaSession.ldapUser, req.ServiceProviderMetadata, req.Assertion); err != nil {
			log.WithError(err).Errorf("Failed to call AlterAssertion on plugin %s", pgName)
		}
	}

	return nil
}
