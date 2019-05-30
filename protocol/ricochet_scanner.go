package protocol

import (
	"fmt"
	"github.com/s-rah/go-ricochet"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
)

// Ricochet protocol scanner instance
type RicochetProtocolScanner struct {
}

// Internal type used to keep track of a the protocol state for checking a
// ricochet server
type ricochetServiceChecker struct {
	osc      *config.OnionScanConfig
	ricochet *goricochet.Ricochet
	// Channel used to pass result back to main thread
	status chan bool
}

// OnReady is called once a Server has been established (by calling Listen)
func (rsc *ricochetServiceChecker) OnReady() {
}

// OnConnect is called when a client or server sucessfully passes Version Negotiation.
func (rsc *ricochetServiceChecker) OnConnect(oc *goricochet.OpenConnection) {
	rsc.osc.LogInfo(fmt.Sprintf("Ricochet version negotiation completed for %s", oc.OtherHostname))
	oc.IsAuthed = true // Connections to Servers are Considered Authenticated by Default
	oc.Authenticate(1)
}

// OnDisconnect is called when a connection is closed
func (rsc *ricochetServiceChecker) OnDisconnect(oc *goricochet.OpenConnection) {
	rsc.status <- false
}

// OnAuthenticationRequest is called when a client requests Authentication
func (rsc *ricochetServiceChecker) OnAuthenticationRequest(oc *goricochet.OpenConnection, channelID int32, clientCookie [16]byte) {
}

// OnAuthenticationChallenge constructs a valid authentication challenge to the serverCookie
func (rsc *ricochetServiceChecker) OnAuthenticationChallenge(oc *goricochet.OpenConnection, channelID int32, serverCookie [16]byte) {
	rsc.osc.LogInfo("Authentication challenge received, disconnecting\n")
	rsc.status <- true
	oc.Close()
}

// OnAuthenticationProof is called when a client sends Proof for an existing authentication challenge
func (rsc *ricochetServiceChecker) OnAuthenticationProof(oc *goricochet.OpenConnection, channelID int32, publicKey []byte, signature []byte, isKnownContact bool) {
}

// OnAuthenticationResult is called once a server has returned the result of the Proof Verification
func (rsc *ricochetServiceChecker) OnAuthenticationResult(oc *goricochet.OpenConnection, channelID int32, result bool, isKnownContact bool) {
	oc.IsAuthed = result
}

// IsKnownContact allows a caller to determine if a hostname an authorized contact.
func (rsc *ricochetServiceChecker) IsKnownContact(hostname string) bool {
	return false
}

// OnContactRequest is called when a client sends a new contact request
func (rsc *ricochetServiceChecker) OnContactRequest(oc *goricochet.OpenConnection, channelID int32, nick string, message string) {
}

// OnContactRequestAck is called when a server sends a reply to an existing contact request
func (rsc *ricochetServiceChecker) OnContactRequestAck(oc *goricochet.OpenConnection, channelID int32, status string) {
}

// OnOpenChannelRequest is called when a client or server requests to open a new channel
func (rsc *ricochetServiceChecker) OnOpenChannelRequest(oc *goricochet.OpenConnection, channelID int32, channelType string) {
	oc.AckOpenChannel(channelID, channelType)
}

// OnOpenChannelRequestSuccess is called when a client or server responds to an open channel request
func (rsc *ricochetServiceChecker) OnOpenChannelRequestSuccess(oc *goricochet.OpenConnection, channelID int32) {
}

// OnChannelClose is called when a client or server closes an existing channel
func (rsc *ricochetServiceChecker) OnChannelClosed(oc *goricochet.OpenConnection, channelID int32) {
}

// OnChatMessage is called when a new chat message is received.
func (rsc *ricochetServiceChecker) OnChatMessage(oc *goricochet.OpenConnection, channelID int32, messageID int32, message string) {
	oc.AckChatMessage(channelID, messageID)
}

// OnChatMessageAck is called when a new chat message is ascknowledged.
func (rsc *ricochetServiceChecker) OnChatMessageAck(oc *goricochet.OpenConnection, channelID int32, messageID int32) {
}

// OnFailedChannelOpen is called when a server fails to open a channel
func (rsc *ricochetServiceChecker) OnFailedChannelOpen(oc *goricochet.OpenConnection, channelID int32, errorType string) {
	oc.UnsetChannel(channelID)
}

// OnGenericError is called when a generalized error is returned from the peer
func (rsc *ricochetServiceChecker) OnGenericError(oc *goricochet.OpenConnection, channelID int32) {
	oc.RejectOpenChannel(channelID, "GenericError")
}

//OnUnknownTypeError is called when an unknown type error is returned from the peer
func (rsc *ricochetServiceChecker) OnUnknownTypeError(oc *goricochet.OpenConnection, channelID int32) {
	oc.RejectOpenChannel(channelID, "UnknownTypeError")
}

// OnUnauthorizedError is called when an unathorized error is returned from the peer
func (rsc *ricochetServiceChecker) OnUnauthorizedError(oc *goricochet.OpenConnection, channelID int32) {
	oc.RejectOpenChannel(channelID, "UnauthorizedError")
}

// OnBadUsageError is called when a bad usage error is returned from the peer
func (rsc *ricochetServiceChecker) OnBadUsageError(oc *goricochet.OpenConnection, channelID int32) {
	oc.RejectOpenChannel(channelID, "BadUsageError")
}

// OnFailedError is called when a failed error is returned from the peer
func (rsc *ricochetServiceChecker) OnFailedError(oc *goricochet.OpenConnection, channelID int32) {
	oc.RejectOpenChannel(channelID, "FailedError")
}

// Perform scan of a hidden service for the Ricochet protocol
func (rps *RicochetProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionScanConfig, report *report.OnionScanReport) {
	osc.LogInfo(fmt.Sprintf("Checking %s ricochet(9878)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 9878, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 9878\n")
		report.RicochetDetected = false
	} else {
		osc.LogInfo("Detected possible ricochet instance\n")
		r := new(goricochet.Ricochet)
		rsc := &ricochetServiceChecker{osc, r, make(chan bool)}
		r.Init()
		go r.ProcessMessages(rsc)
		oc, err := r.ConnectOpen(conn, hiddenService)
		r.RequestStopMessageLoop()
		if err != nil {
			osc.LogInfo(fmt.Sprintf("Ricochet ConnectOpen failed: %s\n", err))
		} else {
			if <-rsc.status {
				osc.LogInfo("Detected working ricochet instance\n")
				report.RicochetDetected = true
			}
			oc.Close()
		}
	}
	if conn != nil {
		conn.Close()
	}
}
