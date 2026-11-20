package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	serviceGuest  = "e629aa43-af11-47c6-aedc-a2dc47f1cc3a"
	protocolName  = "fvca-management/1"
	requestLimit  = 2048
	responseLimit = 4096
)

type client struct {
	address string
	tls     *tls.Config
	key     ed25519.PrivateKey
}

func boundedFile(path string, limit int64, private bool) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return nil, errors.New("expected a bounded regular file")
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Mode().Perm() != 0o600 {
			return nil, errors.New("expected a private runner-owned credential file")
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, errors.New("credential file could not be read within its size bound")
	}
	return data, nil
}

func loadSigner(path string) (ed25519.PrivateKey, error) {
	data, err := boundedFile(path, 4096, true)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one PKCS#8 Ed25519 runner key")
	}
	defer clear(block.Bytes)
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid PKCS#8 runner key")
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("expected an Ed25519 runner key")
	}
	return key, nil
}

func newClient(address, name, certificatePin, caFile, keyFile string) (*client, error) {
	target, err := netip.ParseAddrPort(address)
	ip := target.Addr()
	if err != nil || target.Port() < 1024 || ip.Zone() != "" || ip.Is4In6() ||
		!(ip.IsPrivate() || ip.IsLoopback()) {
		return nil, errors.New("management address must be a literal private IP with an unprivileged port")
	}
	if name == "" || !isDigest(certificatePin) {
		return nil, errors.New("an enrolled TLS server name and leaf certificate SHA-256 are required")
	}
	pin, _ := hex.DecodeString(certificatePin)
	ca, err := boundedFile(caFile, 64*1024, false)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("cannot load the PEM trust bundle from FVCA_MANAGEMENT_CA_FILE")
	}
	key, err := loadSigner(keyFile)
	if err != nil {
		return nil, errors.New("FVCA_OPERATOR_KEY_FILE must name a private runner-owned PKCS#8 Ed25519 key with mode 0600")
	}
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: name,
		NextProtos: []string{protocolName},
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.NegotiatedProtocol != protocolName || len(state.PeerCertificates) == 0 {
				return errors.New("unexpected Host TLS protocol or identity")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if !bytes.Equal(actual[:], pin) {
				return errors.New("Host TLS certificate differs from enrollment")
			}
			return nil
		},
	}
	return &client{address: address, tls: config, key: key}, nil
}

func isDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type binding struct {
	Revision uint64 `json:"revision"`
	SHA256   string `json:"sha256"`
}

type settings struct {
	Revision  *uint64 `json:"revision"`
	SHA256    *string `json:"sha256"`
	VCPUs     int64   `json:"vcpus"`
	MemoryMiB int64   `json:"memory_mib"`
}

func (s settings) binding() *binding {
	if s.Revision == nil || s.SHA256 == nil {
		return nil
	}
	return &binding{Revision: *s.Revision, SHA256: *s.SHA256}
}

func (s settings) valid(guest string) bool {
	return machineProfile(s.VCPUs, s.MemoryMiB) && ((s.Revision == nil && s.SHA256 == nil &&
		s.VCPUs == 2 && s.MemoryMiB == 2048) || (s.binding() != nil &&
		*s.Revision > 0 && *s.SHA256 == configurationDigest(guest, *s.Revision, s.VCPUs, s.MemoryMiB)))
}

func machineProfile(cpu, memory int64) bool {
	return cpu >= 1 && cpu <= 4 && memory >= 1024 && memory <= 4096 && memory%256 == 0
}

type release struct {
	Epoch    uint64 `json:"epoch"`
	Sequence uint64 `json:"sequence"`
	SHA256   string `json:"manifest_sha256"`
}

type response struct {
	Schema                string    `json:"schema"`
	Nonce                 string    `json:"nonce"`
	Host                  string    `json:"host"`
	Guest                 string    `json:"guest"`
	Result                string    `json:"result"`
	Code                  string    `json:"code"`
	BootConfiguration     *settings `json:"boot_configuration"`
	ConfigurationEnrolled *bool     `json:"configuration_enrolled"`
	HostTrial             *bool     `json:"host_trial"`
	Observed              *release  `json:"observed_release"`
	Configuration         *settings `json:"configuration"`
	Activation            string    `json:"activation"`
	OperationID           string    `json:"operation_id"`
	OperationState        string    `json:"state"`
}

type request struct {
	Schema    string `json:"schema"`
	Host      string `json:"host"`
	Guest     string `json:"guest"`
	Nonce     string `json:"nonce"`
	IssuedAt  int64  `json:"issued_at"`
	Expires   int64  `json:"expires"`
	Operation any    `json:"operation"`
}

func (c *client) exchange(ctx context.Context, host, guest string, operation any) (response, error) {
	return c.signedExchange(ctx, host, guest, operation, c.key)
}

var errUnknownOperation = errors.New("the Host has no retained operation with this ID")

func (c *client) signedExchange(ctx context.Context, host, guest string, operation any, key ed25519.PrivateKey) (response, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return response{}, errors.New("could not generate a request nonce")
	}
	now := time.Now().Unix()
	sent := request{"fvca-management-request-v1", host, guest, hex.EncodeToString(nonce), now, now + 25, operation}
	body, err := json.Marshal(sent)
	if err != nil || len(body)+ed25519.SignatureSize > requestLimit {
		return response{}, errors.New("management request exceeds its size bound")
	}
	data := binary.BigEndian.AppendUint32(nil, uint32(len(body)+ed25519.SignatureSize))
	data = append(data, ed25519.Sign(key, body)...)
	data = append(data, body...)

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := &tls.Dialer{Config: c.tls}
	conn, err := dialer.DialContext(ctx, "tcp", c.address)
	if err != nil {
		return response{}, fmt.Errorf("could not establish the enrolled Host TLS connection: %w", err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return response{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if n, err := conn.Write(data); err != nil || n != len(data) {
		return response{}, errors.New("could not send the complete management request")
	}
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil || length == 0 || length > responseLimit {
		return response{}, errors.New("Host returned no bounded management response")
	}
	reply := make([]byte, length)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return response{}, errors.New("Host returned an incomplete management response")
	}
	decoder := json.NewDecoder(bytes.NewReader(reply))
	decoder.DisallowUnknownFields()
	var got response
	if err := decoder.Decode(&got); err != nil || decoder.Decode(new(any)) != io.EOF ||
		got.Schema != "fvca-management-response-v1" || got.Host != host ||
		got.Guest != guest || got.Nonce != sent.Nonce {
		return response{}, errors.New("Host response did not match the request schema, identities and nonce")
	}
	if got.Result == "refused" {
		switch got.Code {
		case "stale-configuration":
			return response{}, errors.New("the Host configuration changed during planning; run a new plan")
		case "trial-in-progress":
			return response{}, errors.New("a Host trial is in progress; plan after it resolves")
		case "unknown-configuration-operation":
			return response{}, errUnknownOperation
		case "outside-machine-profile", "configuration-authority-unavailable", "configuration-exhausted",
			"host-state-unavailable", "expired-configuration-plan", "invalid-configuration-plan",
			"configuration-operation-pending", "lifecycle-busy", "outside-host-capacity":
			return response{}, fmt.Errorf("Host refused the configuration request (%s)", got.Code)
		default:
			return response{}, errors.New("Host refused the management request")
		}
	}
	return got, nil
}

type plan struct {
	Active  settings
	Desired settings
	Release *release
	Scope   string
}

func (c *client) status(ctx context.Context, host, guest string) (response, error) {
	status, err := c.exchange(ctx, host, guest, struct {
		Type string `json:"type"`
	}{"status"})
	if err != nil {
		return response{}, err
	}
	if status.Result != "status" || status.BootConfiguration == nil || !status.BootConfiguration.valid(guest) ||
		status.ConfigurationEnrolled == nil || status.HostTrial == nil || status.Code != "" ||
		status.Configuration != nil || status.Activation != "" ||
		status.OperationID != "" || status.OperationState != "" ||
		(status.Observed != nil && (status.Observed.Epoch < 1 || status.Observed.Sequence < 1 || !isDigest(status.Observed.SHA256))) {
		return response{}, errors.New("invalid boot configuration or release in Host status")
	}
	return status, nil
}

func (c *client) preflight(ctx context.Context, host, guest string, cpu, memory int64, observeTrial bool) (plan, error) {
	status, err := c.status(ctx, host, guest)
	if err != nil {
		return plan{}, err
	}
	active := *status.BootConfiguration
	if *status.HostTrial && observeTrial {
		return plan{Active: active, Release: status.Observed, Scope: "trial-in-progress"}, nil
	}
	prior := active.binding()
	approval, err := c.exchange(ctx, host, guest, struct {
		Type      string   `json:"type"`
		Expected  *binding `json:"expected"`
		VCPUs     int64    `json:"vcpus"`
		MemoryMiB int64    `json:"memory_mib"`
	}{"preflight", prior, cpu, memory})
	if err != nil {
		return plan{}, err
	}
	if !*status.ConfigurationEnrolled || *status.HostTrial || approval.Result != "preflight" || approval.Configuration == nil ||
		!approval.Configuration.valid(guest) || approval.Code != "" || approval.BootConfiguration != nil ||
		approval.ConfigurationEnrolled != nil || approval.HostTrial != nil || approval.Observed != nil ||
		approval.OperationState != "" || approval.OperationID != "" {
		return plan{}, errors.New("invalid Host preflight result")
	}
	next := *approval.Configuration
	if next.VCPUs != cpu || next.MemoryMiB != memory {
		return plan{}, errors.New("Host preflight settings differ from the desired CPU or memory")
	}
	if err := requireIntent(guest, active, next, approval.Activation); err != nil {
		return plan{}, err
	}
	return plan{Active: active, Desired: next, Release: status.Observed, Scope: approval.Activation}, nil
}

func requireIntent(guest string, active, next settings, activation string) error {
	previous, candidate := active.binding(), next.binding()
	if active.VCPUs == next.VCPUs && active.MemoryMiB == next.MemoryMiB {
		if activation == "none" && ((previous == nil && candidate == nil) ||
			(previous != nil && candidate != nil && *previous == *candidate)) {
			return nil
		}
		return errors.New("Host attempted a new settings revision for unchanged intent")
	}
	var revision uint64 = 1
	if previous != nil {
		if previous.Revision == math.MaxUint64 {
			return errors.New("the configuration revision is exhausted")
		}
		revision = previous.Revision + 1
	}
	expected := configurationDigest(guest, revision, next.VCPUs, next.MemoryMiB)
	if activation != "host-trial" || candidate == nil || candidate.Revision != revision ||
		candidate.SHA256 != expected {
		return errors.New("preflight did not bind the exact next revision and desired settings")
	}
	return nil
}

func configurationDigest(guest string, revision uint64, vcpus, memory int64) string {
	record := fmt.Sprintf("FVCA-SERVICE-GUEST-VM-2\nguest=%s\nrevision=%d\nvcpus=%d\nmemory_mib=%d\n",
		guest, revision, vcpus, memory)
	digest := sha256.Sum256([]byte(record))
	return hex.EncodeToString(digest[:])
}
