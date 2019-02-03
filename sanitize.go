package sanitize

import (
	"errors"
	"regexp"
	"strings"
)

//Email will sanitize email and return an error if invalid
func Email(email string) (string, error) {
	var validEmail string
	errorInvalid := errors.New("invalid email format")
	if len(email) < 6 || len(email) > 254 {
		return validEmail, errorInvalid
	}
	hostRegexp := regexp.MustCompile("^[^\\s]+\\.[^\\s]+$")
	userRegexp := regexp.MustCompile("^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+$")
	at := strings.LastIndex(email, "@")
	if at <= 0 || at > len(email)-3 {
		return validEmail, errorInvalid
	}

	if !userRegexp.MatchString(email[:at]) || !hostRegexp.MatchString(email[at+1:]) {
		return validEmail, errorInvalid
	}

	validEmail = strings.TrimSpace(email)
	validEmail = strings.TrimRight(validEmail, ".")
	validEmail = strings.ToLower(validEmail)

	return validEmail, nil
}

//Name will sanitize name and return error if invalid
func Name(name string) (string, error) {
	var validName string
	errorInvalid := errors.New("invalid name format")
	if len(name) > 50 || len(name) < 2 {
		return validName, errorInvalid
	}
	nameRegexp := regexp.MustCompile("^[\\p{L}\\s'.-]+$")
	if !nameRegexp.MatchString(name) {
		return validName, errorInvalid
	}
	validName = strings.TrimSpace(name)
	validName = strings.ToUpper(validName)
	return validName, nil
}

//Surname sanitizes surname and return error if invalid
func Surname(surname string) (string, error) {
	var validSurname string
	errorInvalid := errors.New("invalid surname format")
	if len(surname) > 50 || len(surname) < 2 {
		return validSurname, errorInvalid
	}
	surnameRegexp := regexp.MustCompile("^[\\p{L}\\s'.-]+$")
	if !surnameRegexp.MatchString(surname) {
		return validSurname, errorInvalid
	}
	validSurname = surname
	return validSurname, nil
}

//Phone sanitizes phone and return error if invalid
func Phone(phone string) (string, error) {
	var validPhone string
	errorInvalid := errors.New("invalid phone format")
	if len(phone) > 20 || len(phone) < 10 {
		return validPhone, errorInvalid
	}
	reg := regexp.MustCompile(`^[0-9\s+.-]+$`)
	if !reg.MatchString(phone) {
		return validPhone, errorInvalid
	}
	validPhone = strings.TrimSpace(phone)
	return validPhone, nil
}
