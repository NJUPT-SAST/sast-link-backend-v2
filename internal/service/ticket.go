package service

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// TicketType identifies which flow a ticket belongs to.
type TicketType string

const (
	TicketTypeRegister TicketType = "register"
	TicketTypeLogin    TicketType = "login"
	TicketTypeResetPwd TicketType = "reset_pwd"
)

// TTL returns the expiry duration for each ticket type.
func (t TicketType) TTL() time.Duration {
	switch t {
	case TicketTypeResetPwd:
		return 6 * time.Minute
	default:
		return 5 * time.Minute
	}
}

// TicketStatus is the state of a ticket.
type TicketStatus string

const (
	TicketStatusPending  TicketStatus = "pending"
	TicketStatusVerified TicketStatus = "verified"
)

// TicketData stores the business payload associated with a ticket.
type TicketData struct {
	Email     string       `json:"email"`
	Type      TicketType   `json:"type"`
	Status    TicketStatus `json:"status"`
	Code      string       `json:"code"`
	ExpiresAt time.Time    `json:"expires_at"`
}

// GenerateTicket creates a random ticket ID and its associated TicketData.
// The code field is left empty — it will be filled in when the email is sent.
func GenerateTicket(email string, t TicketType) (string, *TicketData, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	ticketID := hex.EncodeToString(b)

	data := &TicketData{
		Email:     email,
		Type:      t,
		Status:    TicketStatusPending,
		ExpiresAt: time.Now().Add(t.TTL()),
	}
	return ticketID, data, nil
}
