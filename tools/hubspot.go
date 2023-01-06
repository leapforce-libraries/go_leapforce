package tools

import (
	"encoding/base64"
	"encoding/json"
	"github.com/leapforce-applications/api/utils"
	errortools "github.com/leapforce-libraries/go_errortools"
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

	encrypted, err := utils.Encrypt(b, cipherKey)
	if err != nil {
		return "", errortools.ErrorMessage(err)
	}

	return base64.StdEncoding.EncodeToString([]byte(encrypted)), nil
}
