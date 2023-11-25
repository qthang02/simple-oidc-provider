package models

type CallbackRequest struct {
	RequestID  string `json:"request_id,omitempty"`
	AuthUserID string `json:"auth_user_id,omitempty"`
}

func NewCallbackRequest(requestId, userId string) *CallbackRequest {
	return &CallbackRequest{
		RequestID:  requestId,
		AuthUserID: userId,
	}
}

func (cb *CallbackRequest) GetRequestID() string {
	return cb.RequestID
}

func (cb *CallbackRequest) GetAuthUserID() string {
	return cb.AuthUserID
}
