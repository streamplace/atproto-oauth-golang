package oauth

import (
	"encoding/json"
	"fmt"
	"net/url"
)

type OauthProtectedResource struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceDocumentation  string   `json:"resource_documentation"`
}

func (opr *OauthProtectedResource) UnmarshalJSON(b []byte) error {
	type Tmp OauthProtectedResource
	var tmp Tmp

	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}

	*opr = OauthProtectedResource(tmp)

	return nil
}

type OauthAuthorizationMetadata struct {
	Issuer                                     string   `json:"issuer"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestUriParameterSupported               bool     `json:"request_uri_parameter_supported"`
	RequireRequestUriRegistration              *bool    `json:"require_request_uri_registration,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	UILocalesSupported                         []string `json:"ui_locales_supported"`
	DisplayValuesSupported                     []string `json:"display_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	AuthorizationResponseISSParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported"`
	JwksUri                                    string   `json:"jwks_uri"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	PushedAuthorizationRequestEndpoint         string   `json:"pushed_authorization_request_endpoint"`
	RequirePushedAuthorizationRequests         bool     `json:"require_pushed_authorization_requests"`
	DpopSigningAlgValuesSupported              []string `json:"dpop_signing_alg_values_supported"`
	ProtectedResources                         []string `json:"protected_resources"`
	ClientIDMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported"`
}

func (oam *OauthAuthorizationMetadata) Validate(fetch_url *url.URL) error {
	if fetch_url == nil {
		return fmt.Errorf("fetch_url was nil")
	}

	iu, err := url.Parse(oam.Issuer)
	if err != nil {
		return err
	}

	if iu.Hostname() != fetch_url.Hostname() {
		return fmt.Errorf("issuer hostname does not match fetch url hostname")
	}

	if iu.Scheme != "https" {
		return fmt.Errorf("issuer url is not https")
	}

	if iu.Port() != "" {
		return fmt.Errorf("issuer port is not empty")
	}

	if iu.Path != "" && iu.Path != "/" {
		return fmt.Errorf("issuer path is not /")
	}

	if iu.RawQuery != "" {
		return fmt.Errorf("issuer url params are not empty")
	}

	if !tokenInSet("code", oam.ResponseTypesSupported) {
		return fmt.Errorf("`code` is not in response_types_supported")
	}

	if !tokenInSet("authorization_code", oam.GrantTypesSupported) {
		return fmt.Errorf("`authorization_code` is not in grant_types_supported")
	}

	if !tokenInSet("refresh_token", oam.GrantTypesSupported) {
		return fmt.Errorf("`refresh_token` is not in grant_types_supported")
	}

	if !tokenInSet("S256", oam.CodeChallengeMethodsSupported) {
		return fmt.Errorf("`S256` is not in code_challenge_methods_supported")
	}

	if !tokenInSet("none", oam.TokenEndpointAuthMethodsSupported) {
		return fmt.Errorf("`none` is not in token_endpoint_auth_methods_supported")
	}

	if !tokenInSet("private_key_jwt", oam.TokenEndpointAuthMethodsSupported) {
		return fmt.Errorf("`private_key_jwt` is not in token_endpoint_auth_methods_supported")
	}

	if !tokenInSet("ES256", oam.TokenEndpointAuthSigningAlgValuesSupported) {
		return fmt.Errorf("`ES256` is not in token_endpoint_auth_signing_alg_values_supported")
	}

	if !tokenInSet("atproto", oam.ScopesSupported) {
		return fmt.Errorf("`atproto` is not in scopes_supported")
	}

	if oam.AuthorizationResponseISSParameterSupported != true {
		return fmt.Errorf("authorization_response_iss_parameter_supported is not true")
	}

	if oam.PushedAuthorizationRequestEndpoint == "" {
		return fmt.Errorf("pushed_authorization_request_endpoint is empty")
	}

	if oam.RequirePushedAuthorizationRequests == false {
		return fmt.Errorf("require_pushed_authorization_requests is false")
	}

	if !tokenInSet("ES256", oam.DpopSigningAlgValuesSupported) {
		return fmt.Errorf("`ES256` is not in dpop_signing_alg_values_supported")
	}

	if oam.RequireRequestUriRegistration != nil && *oam.RequireRequestUriRegistration == false {
		return fmt.Errorf("require_request_uri_registration present in metadata and was false")
	}

	if oam.ClientIDMetadataDocumentSupported == false {
		return fmt.Errorf("client_id_metadata_document_supported was false")
	}

	return nil
}

func (oam *OauthAuthorizationMetadata) UnmarshalJSON(b []byte) error {
	type Tmp OauthAuthorizationMetadata
	var tmp Tmp

	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}

	*oam = OauthAuthorizationMetadata(tmp)

	return nil
}
