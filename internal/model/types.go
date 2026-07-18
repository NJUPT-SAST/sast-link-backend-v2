// Package model defines persistence entities for the V001 PostgreSQL schema.
package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
)

// UserRole is a value from PostgreSQL's user_role_enum.
type UserRole string

const (
	UserRoleFreshman UserRole = "freshman"
	UserRoleMember   UserRole = "member"
	UserRoleLecturer UserRole = "lecturer"
	UserRoleAdmin    UserRole = "admin"
)

// Department is a value from PostgreSQL's department_enum.
type Department string

const (
	DepartmentSoftware Department = "software"
	DepartmentMedia    Department = "media"
)

// LoginMethod is a value from PostgreSQL's login_method_enum.
type LoginMethod string

const (
	LoginMethodGitHub    LoginMethod = "github"
	LoginMethodLark      LoginMethod = "lark"
	LoginMethodOtherMail LoginMethod = "other_mail"
)

// UserState is a value from PostgreSQL's state_enum.
type UserState string

const (
	UserStateDeleted     UserState = "is_deleted"
	UserStateOnSAST      UserState = "on_sast"
	UserStateRetiredSAST UserState = "retired_sast"
	UserStateNJUPTer     UserState = "njupter"
)

// EmailType is a value from PostgreSQL's email_enum.
type EmailType string

const (
	EmailTypeSAST  EmailType = "sast_email"
	EmailTypeNJUpt EmailType = "njupt_email"
)

// ClientType is a value from PostgreSQL's client_enum.
type ClientType string

const (
	ClientTypeFirstParty ClientType = "first_party"
	ClientTypeThirdParty ClientType = "third_party"
)

// College is a value from PostgreSQL's college_enum.
type College string

const (
	CollegeBellHonors                             College = "贝尔英才学院"
	CollegeCommunicationAndInformationEngineering College = "通信与信息工程学院"
	CollegeOptoelectronicEngineering              College = "电光柔学院"
	CollegeIntegratedCircuitScienceAndEngineering College = "集成电路科学与工程学院（产教融合学院）"
	CollegeComputerSoftwareCybersecurity          College = "计算机学院、软件学院、网络空间安全学院"
	CollegeAutomation                             College = "自动化学院"
	CollegeArtificialIntelligence                 College = "人工智能学院"
	CollegeMaterialsScienceAndEngineering         College = "材料科学与工程学院"
	CollegeChemistryAndLifeScience                College = "化学与生命科学学院"
	CollegeInternetOfThings                       College = "物联网学院"
	CollegeScience                                College = "理学院"
	CollegeModernPostAndIntelligentTransportation College = "现代邮政学院、智慧交通学院"
	CollegeDigitalMediaAndDesignArt               College = "数字媒体与设计艺术学院"
	CollegeManagement                             College = "管理学院"
	CollegeEconomics                              College = "经济学院"
	CollegeSociologyPopulationAndSocialWork       College = "社会与人口学院、社会工作学院"
	CollegeForeignLanguages                       College = "外国语学院"
	CollegeEducationScienceAndTechnology          College = "教育科学与技术学院"
	CollegePortland                               College = "波特兰学院"
	CollegeOther                                  College = "其他"
)

// StringArray is a one-dimensional PostgreSQL text[] value. A nil slice maps
// to SQL NULL; a non-nil empty slice maps to the empty PostgreSQL array ({}).
type StringArray []string

// Scan implements sql.Scanner.
func (a *StringArray) Scan(value any) error {
	if value == nil {
		*a = nil
		return nil
	}

	var literal string
	switch typedValue := value.(type) {
	case []byte:
		literal = string(typedValue)
	case string:
		literal = typedValue
	default:
		return fmt.Errorf("scan PostgreSQL text[]: unsupported type %T", value)
	}

	parsed, err := parseStringArray(literal)
	if err != nil {
		return err
	}
	*a = StringArray(parsed)
	return nil
}

// Value implements driver.Valuer.
func (a StringArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	for _, element := range a {
		if strings.ContainsRune(element, '\x00') {
			return nil, fmt.Errorf("value PostgreSQL text[]: element contains NUL")
		}
	}

	var builder strings.Builder
	builder.WriteByte('{')
	for index, element := range a {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteByte('"')
		for _, character := range element {
			if character == '\\' || character == '"' {
				builder.WriteByte('\\')
			}
			builder.WriteRune(character)
		}
		builder.WriteByte('"')
	}
	builder.WriteByte('}')
	return builder.String(), nil
}

func parseStringArray(literal string) ([]string, error) {
	if len(literal) < 2 || literal[0] != '{' || literal[len(literal)-1] != '}' {
		return nil, fmt.Errorf("scan PostgreSQL text[]: invalid array literal %q", literal)
	}
	if literal == "{}" {
		return []string{}, nil
	}

	values := make([]string, 0)
	for offset := 1; offset < len(literal)-1; {
		value, nextOffset, quoted, err := parseStringArrayElement(literal, offset)
		if err != nil {
			return nil, err
		}
		if !quoted && value == "NULL" {
			return nil, fmt.Errorf("scan PostgreSQL text[]: NULL element is unsupported")
		}
		values = append(values, value)
		offset = nextOffset
		if offset == len(literal)-1 {
			break
		}
		if literal[offset] != ',' {
			return nil, fmt.Errorf("scan PostgreSQL text[]: expected comma at offset %d", offset)
		}
		offset++
		if offset == len(literal)-1 {
			return nil, fmt.Errorf("scan PostgreSQL text[]: missing element after comma")
		}
	}
	return values, nil
}

func parseStringArrayElement(literal string, offset int) (string, int, bool, error) {
	if literal[offset] == '"' {
		var builder strings.Builder
		for offset = offset + 1; offset < len(literal)-1; offset++ {
			character := literal[offset]
			switch character {
			case '\\':
				offset++
				if offset >= len(literal)-1 {
					return "", 0, false, fmt.Errorf("scan PostgreSQL text[]: dangling escape")
				}
				builder.WriteByte(literal[offset])
			case '"':
				return builder.String(), offset + 1, true, nil
			default:
				builder.WriteByte(character)
			}
		}
		return "", 0, false, fmt.Errorf("scan PostgreSQL text[]: unterminated quoted element")
	}

	startOffset := offset
	var builder strings.Builder
	for ; offset < len(literal)-1 && literal[offset] != ','; offset++ {
		if literal[offset] == '\\' {
			offset++
			if offset >= len(literal)-1 {
				return "", 0, false, fmt.Errorf("scan PostgreSQL text[]: dangling escape")
			}
		}
		builder.WriteByte(literal[offset])
	}
	if offset == startOffset {
		return "", 0, false, fmt.Errorf("scan PostgreSQL text[]: empty unquoted element")
	}
	return builder.String(), offset, false, nil
}

// JSONB is a PostgreSQL JSONB value.
type JSONB json.RawMessage

// Scan implements sql.Scanner.
func (j *JSONB) Scan(value any) error {
	if value == nil {
		*j = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("scan JSONB: unsupported type %T", value)
	}
	*j = append((*j)[:0], bytes...)
	return nil
}

// Value implements driver.Valuer.
func (j JSONB) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	if !json.Valid(j) {
		return nil, fmt.Errorf("JSONB value is invalid JSON")
	}
	return []byte(j), nil
}
