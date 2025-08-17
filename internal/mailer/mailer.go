package mailer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

// SMTPMailer sends emails using a basic SMTP server. It supports STARTTLS if the server advertises it.
type SMTPMailer struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

// Send sends a plain text email.
func (m *SMTPMailer) Send(to string, subject string, body string) error {
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("missing recipient")
	}
	from := m.From
	if strings.TrimSpace(from) == "" {
		from = m.Username
	}

	addr := net.JoinHostPort(m.Host, m.Port)

	// Prepare message
	msg := strings.Builder{}
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	// Establish connection
	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()

	// Attempt STARTTLS if available
	if ok, _ := client.Extension("STARTTLS"); ok {
		cfg := &tls.Config{ServerName: m.Host}
		if err := client.StartTLS(cfg); err != nil {
			return err
		}
	}

	// Authenticate if credentials provided
	if strings.TrimSpace(m.Username) != "" {
		auth := smtp.PlainAuth("", m.Username, m.Password, m.Host)
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}
	}

	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg.String())); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
