package vpn

import (
	"errors"
	"fmt"
	"io"
	"net"
)

const commandKickout byte = 0x32

var (
	ErrEndpointComplianceRequired = errors.New("gateway requires endpoint compliance checks")
	ErrReauthenticationRequired   = errors.New("gateway requires fresh authentication; the current tunnel is closed")
	ErrSessionRevoked             = errors.New("gateway revoked this session; no automatic reconnect")
	ErrSessionLimit               = errors.New("local maximum session duration reached; the current tunnel is closed")
)

// EndpointRequirement reports gateway policy without claiming that checks passed.
// Check and Mode are protocol identifiers, not local security posture results.
type EndpointRequirement struct {
	Check byte
	Mode  byte
}

func (e *EndpointRequirement) Error() string {
	return fmt.Sprintf("%v (check=%d, mode=%d); use the official client with the required security components", ErrEndpointComplianceRequired, e.Check, e.Mode)
}

func (e *EndpointRequirement) Unwrap() error { return ErrEndpointComplianceRequired }

// ChannelError distinguishes an interrupted tunnel from authentication rejection.
type ChannelError struct {
	Channel string
	Err     error
}

func (e *ChannelError) Error() string { return fmt.Sprintf("%s channel: %v", e.Channel, e.Err) }
func (e *ChannelError) Unwrap() error { return e.Err }

// Reconnectable permits a new complete login after interruption or a fresh-auth
// request. Revocation, policy rejection, and malformed protocol data never retry.
func Reconnectable(err error) bool {
	if errors.Is(err, ErrReauthenticationRequired) || errors.Is(err, ErrSessionLimit) {
		return true
	}
	var channel *ChannelError
	if !errors.As(err, &channel) {
		return false
	}
	var network net.Error
	return errors.As(channel.Err, &network) || errors.Is(channel.Err, io.EOF) || errors.Is(channel.Err, io.ErrUnexpectedEOF)
}
