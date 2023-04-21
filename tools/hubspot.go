package tools

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	errortools "github.com/leapforce-libraries/go_errortools"
	utilities "github.com/leapforce-libraries/go_utilities"
	"time"
)

const (
	PropNoBulk       string = "lf_no_bulk"
	PropNoBulkLegacy string = "no_bulk"

	PropValidatePhoneNumbers       string = "lf_validate_phone_numbers"
	PropValidatePhoneNumbersLegacy string = "validate_phone_number_s_"
	PropMobilePhoneValidity        string = "lf_mobile_phone_validity"
	PropMobilePhoneValidityLegacy  string = "mobile_phone_validity"
	PropPhoneValidity              string = "lf_phone_validity"
	PropPhoneValidityLegacy        string = "phone_validity"

	PropValidateEmail       string = "lf_validate_email"
	PropValidateEmailLegacy string = "validate_email"
	PropEmailValidity       string = "lf_email_validity"
	PropEmailValidityLegacy string = "email_validity"

	PropSearchLinkedInProfilePage       string = "lf_search_linkedin_profile_page"
	PropSearchLinkedInProfilePageLegacy string = "search_linkedin_profile_page"
	PropLinkedInProfilePage             string = "lf_linkedin_profile_page"
	PropLinkedInProfilePageLegacy       string = "linkedin_org"

	PropSearchLinkedInCompanyPage string = "lf_search_linkedin_company_page"
	PropLinkedInCompanyPage       string = "lf_linkedin_company_page"

	PropValidatePostcode  string = "lf_validate_postcode"
	PropPostcodeValidity  string = "lf_postcode_validity"
	PropBagOppervlakte    string = "bag_oppervlakte"
	PropBagGebruiksdoelen string = "bag_gebruiksdoelen"

	PropGetKvkInfo              string = "lf_get_kvk_info"
	PropGetKvkInfoLegacy        string = "get_kvk_info"
	PropKvkNummer               string = "kvk_nummer"
	PropKvkPotentieleKvkNummers string = "kvk_potentiele_kvk_nummers"
	PropKvkVestigingsnummer     string = "kvk_vestigingsnummer"
	PropKvkRsin                 string = "kvk_rsin"
	PropKvkTypeRechtspersoon    string = "kvk_type_rechtspersoon"
	PropKvkAantalMedewerkers    string = "kvk_aantal_medewerkers"
	PropKvkSbiActiviteiten      string = "kvk_sbi_activiteiten"
	PropKvkRechtsvorm           string = "kvk_rechtsvorm"
	PropKvkHandelsnaam          string = "kvk_handelsnaam"
	PropKvkWebsites             string = "kvk_websites"

	PropCbsPercEenpersoonsHuishoudens string = "cbs_perc_eenpersoons_huishoudens"
	PropCbsGemiddeldeWoningwaarde     string = "cbs_gem_woz_waarde"
	PropCbsPercKoopwoningen           string = "cbs_perc_koopwoningen"
	PropCbsGemInkomenPerInwoner       string = "cbs_gem_inkomen_per_inwoner"
	PropCbsMediaanVermogen            string = "cbs_mediaan_vermogen"
	PropCbsPercKinderen               string = "cbs_perc_kinderen"
	PropCbsPercAdolescenten           string = "cbs_perc_adolescenten"
	PropCbsPercJongvolwassenen        string = "cbs_perc_jongvolwassenen"
	PropCbsPercVolwassenen            string = "cbs_perc_volwassenen"
	PropCbsPercSenioren               string = "cbs_perc_senioren"
	PropCbsMateVanStedelijkheid       string = "cbs_mate_van_stedelijkheid"
	PropCbsBedrijfsvestigingen        string = "cbs_bedrijfsvestigingen"
	PropCbsBedrijfsvestigingenPerHa   string = "cbs_bedrijfsvestigingen_per_ha"
	PropCbsPersonenautosPerHuishouden string = "cbs_personenautos_per_huishouden"
	PropCbsAfstandHuisartsenpost      string = "cbs_afstand_huisartsenpost"
	PropCbsAfstandGroteSupermarkt     string = "cbs_afstand_grote_supermarkt"
	PropCbsAfstandKinderdagverblijf   string = "cbs_afstand_kinderdagverblijf"
	PropCbsAfstandSchool              string = "cbs_afstand_school"
)

func ValidatePhoneEncrypt(portalId string, objectType string, objectId string, phoneNumber string, region string, field string, targetField string, cipherKey string) (string, *errortools.Error) {
	var values = make(map[string]string)
	values["portal_id"] = portalId
	values["object_type"] = objectType
	values["object_id"] = objectId
	values["phone"] = phoneNumber
	values["region"] = region
	values["field"] = field
	values["target_field"] = targetField
	values["ts"] = fmt.Sprintf("%v", time.Now().UnixMilli())

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

func ValidateEmailEncrypt(portalId string, objectType string, objectId string, email string, targetField string, cipherKey string) (string, *errortools.Error) {
	var values = make(map[string]string)
	values["portal_id"] = portalId
	values["object_type"] = objectType
	values["object_id"] = objectId
	values["email"] = email
	values["target_field"] = targetField
	values["ts"] = fmt.Sprintf("%v", time.Now().UnixMilli())

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

func ValidatePostcodeEncrypt(portalId string, objectType string, objectId string, street string, postcode string, city string, country string, cbsInfo bool, targetField string, cipherKey string) (string, *errortools.Error) {
	var values = make(map[string]string)
	values["portal_id"] = portalId
	values["object_type"] = objectType
	values["object_id"] = objectId
	values["street"] = street
	values["postcode"] = postcode
	values["city"] = city
	values["country"] = country
	values["cbs_info"] = fmt.Sprintf("%v", cbsInfo)
	values["target_field"] = targetField
	values["ts"] = fmt.Sprintf("%v", time.Now().UnixMilli())

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

func SearchLinkedInCompanyPageEncrypt(portalId string, objectType string, objectId string, name string, city string, domain string, pageUrl string, pageTitle string, targetField string, cipherKey string) (string, *errortools.Error) {
	var values = make(map[string]string)
	values["portal_id"] = portalId
	values["object_type"] = objectType
	values["object_id"] = objectId
	values["name"] = name
	values["city"] = city
	values["domain"] = domain
	values["page_url"] = pageUrl
	values["page_title"] = pageTitle
	values["target_field"] = targetField
	values["ts"] = fmt.Sprintf("%v", time.Now().UnixMilli())

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

func SearchLinkedInProfilePageEncrypt(portalId string, objectType string, objectId string, firstName string, lastName string, companyName string, profileUrl string, profileTitle string, targetField string, cipherKey string) (string, *errortools.Error) {
	var values = make(map[string]string)
	values["portal_id"] = portalId
	values["object_type"] = objectType
	values["object_id"] = objectId
	values["first_name"] = firstName
	values["last_name"] = lastName
	values["company_name"] = companyName
	values["profile_url"] = profileUrl
	values["profile_title"] = profileTitle
	values["target_field"] = targetField
	values["ts"] = fmt.Sprintf("%v", time.Now().UnixMilli())

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
	values["ts"] = fmt.Sprintf("%v", time.Now().UnixMilli())

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
