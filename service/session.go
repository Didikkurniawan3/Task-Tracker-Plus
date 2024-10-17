package service

import (
	"errors"

	"a21hc3NpZ25tZW50/model"
	repo "a21hc3NpZ25tZW50/repository"
)

type SessionService interface {
	GetSessionByEmail(email string) (model.Session, error)
}

type sessionService struct {
	sessionRepo repo.SessionRepository
}

func NewSessionService(sessionRepo repo.SessionRepository) SessionService {
	return &sessionService{sessionRepo: sessionRepo}
}

func (s *sessionService) GetSessionByEmail(email string) (model.Session, error) {
	session, err := s.sessionRepo.SessionAvailEmail(email)
	if err != nil {
		return model.Session{}, err
	}
	if session.Email == "" {
		return model.Session{}, errors.New("Session not found")
	}
	return session, nil
}

