package tools

import (
	"encoding/base64"
	"encoding/json"
	errortools "github.com/leapforce-libraries/go_errortools"
	utilities "github.com/leapforce-libraries/go_utilities"
)

func ValidatePhoneEncrypt(portalId string, objectType string, objectId string, phoneNumber string, region string, field string, cipherKey string) (string, *errortools.Error) {
	var values = make(map[string]string)
	values["portal_id"] = portalId
	values["object_type"] = objectType
	values["object_id"] = objectId
	values["phone"] = phoneNumber
	values["region"] = region
	values["field"] = field

	b, err := json.Marshal(values)
	if err != nil {
		return "", errortools.ErrorMessage(err)
	}

	encrypted, err := utilities.Encrypt(b, cipherKey)
	if err != nil {
		return "", errortools.ErrorMessage(err)
	}

	return base64.StdEncoding.EncodeToString([]byte(encrypted)), nil
}

func ValidateEmailEncrypt(portalId string, objectType string, objectId string, email string, cipherKey string) (string, *errortools.Error) {
	var values = make(map[string]string)
	values["portal_id"] = portalId
	values["object_type"] = objectType
	values["object_id"] = objectId
	values["email"] = email

	b, err := json.Marshal(values)
	if err != nil {
		return "", errortools.ErrorMessage(err)
	}

	encrypted, err := utilities.Encrypt(b, cipherKey)
	if err != nil {
		return "", errortools.ErrorMessage(err)
	}

	return base64.StdEncoding.EncodeToString([]byte(encrypted)), nil
}

func SearchLinkedInProfilePageEncrypt(portalId string, objectType string, objectId string, firstName string, lastName string, companyName string, cipherKey string) (string, *errortools.Error) {
	var values = make(map[string]string)
	values["portal_id"] = portalId
	values["object_type"] = objectType
	values["object_id"] = objectId
	values["first_name"] = firstName
	values["last_name"] = lastName
	values["company_name"] = companyName

	b, err := json.Marshal(values)
	if err != nil {
		return "", errortools.ErrorMessage(err)
	}

	encrypted, err := utilities.Encrypt(b, cipherKey)
	if err != nil {
		return "", errortools.ErrorMessage(err)
	}

	return base64.StdEncoding.EncodeToString([]byte(encrypted)), nil
}

func GetKvkInfoEncrypt(portalId string, objectType string, objectId string, kvkNumber *string, name *string, zip *string, address *string, country *string, cipherKey string) (string, *errortools.Error) {
	var values = make(map[string]string)
	values["portal_id"] = portalId
	values["object_type"] = objectType
	values["object_id"] = objectId
	if kvkNumber != nil {
		values["kvk-number"] = *kvkNumber
	}
	if name != nil {
		values["company-name"] = *name
	}
	if zip != nil {
		values["zip"] = *zip
	}
	if address != nil {
		values["street"] = *address
	}
	if country != nil {
		values["country"] = *country
	}

	b, err := json.Marshal(values)
	if err != nil {
		return "", errortools.ErrorMessage(err)
	}

	encrypted, err := utilities.Encrypt(b, cipherKey)
	if err != nil {
		return "", errortools.ErrorMessage(err)
	}

	return base64.StdEncoding.EncodeToString([]byte(encrypted)), nil
}
