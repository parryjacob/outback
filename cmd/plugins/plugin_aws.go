package main

import (
	"errors"
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/parryjacob/outback"
	"github.com/parryjacob/saml"
)

// AWSConfig describes the configuration for this plugin
type AWSConfig struct {
	AccountID    string
	ProviderName string
	Roles        []awsRole `toml:"role"`
}

type awsRole struct {
	Group string
	Role  string
}

var awsConfig *AWSConfig

// Initialize will load config, etc for the AWS plugin
func Initialize(oa *outback.OutbackApp, pluginName string) error {
	log.Debug("Initializing AWS plugin...")
	awsConfig = &AWSConfig{}
	if err := oa.Config.DecodePluginConfig(pluginName, awsConfig); err != nil {
		log.WithError(err).Error("Failed to decode AWS config!")
		return err
	}

	if len(awsConfig.AccountID) == 0 {
		return errors.New("AWS AccountID must be provided")
	}

	return nil
}

// getRolesForUser will return the SAML AttributeValues for this user
func getRolesForUser(user *outback.LDAPUser) []saml.AttributeValue {
	groupVals := []saml.AttributeValue{}

	for _, role := range awsConfig.Roles {
		if user.HasGroup(role.Group) {
			groupVals = append(groupVals, saml.AttributeValue{
				Type:  "xs:string",
				Value: roleToSAMLARN(role.Role),
			})
		}
	}

	return groupVals
}

// AlterAttributes will alter responses to AWS' SAML endpoint to add the
// required attributes
func AlterAttributes(user *outback.LDAPUser, sp *saml.EntityDescriptor) ([]saml.Attribute, error) {
	attrs := make([]saml.Attribute, 0)

	// We only want to release the Amazon-specific attributes
	// to Amazon
	if sp.EntityID != "urn:amazon:webservices" {
		return attrs, nil
	}

	// Role mappings
	attrs = append(attrs, saml.Attribute{
		FriendlyName: "awsroles",
		Name:         "https://aws.amazon.com/SAML/Attributes/Role",
		Values:       getRolesForUser(user),
	})

	// Username
	attrs = append(attrs, saml.Attribute{
		FriendlyName: "awsusername",
		Name:         "https://aws.amazon.com/SAML/Attributes/RoleSessionName",
		Values: []saml.AttributeValue{{
			Type:  "xs:string",
			Value: user.Username,
		}},
	})

	return attrs, nil
}

// roleToSAMLARN will take a role and convert it to a SAML value for passing to
// AWS' SAML SP
func roleToSAMLARN(role string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s,arn:aws:iam::%s:saml-provider/%s",
		awsConfig.AccountID, role, awsConfig.AccountID, awsConfig.ProviderName)
}
