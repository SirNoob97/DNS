package dns

import (
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type MockPacketConn struct{}

func (m MockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, nil
}

func (m MockPacketConn) Close() error {
	return nil
}

func (m MockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}

func (m MockPacketConn) LocalAddr() net.Addr {
	return nil
}

func (m MockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m MockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m MockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestHandlePacket(t *testing.T) {
	names := []string{"www.example.com.", "www.google.com."}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	for _, name := range names {
		msg := dnsmessage.Message{
			Header: dnsmessage.Header{
				RCode:            dnsmessage.RCode(0),
				ID:               uint16(rnd.Intn(int(^uint16(0)))),
				OpCode:           dnsmessage.OpCode(0),
				Response:         false,
				AuthenticData:    false,
				RecursionDesired: false,
			},
			Questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName(name),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
		}
		buff, err := msg.Pack()
		if err != nil {
			t.Fatalf("Packet ERROR: %s", err)
		}

		err = handlePacket(MockPacketConn{}, &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, buff)
		if err != nil {
			t.Fatalf("Server ERROR: %s", err)
		}
	}
}

func TestOutgoingDnsQuery(t *testing.T) {
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("com."),
		Type:  dnsmessage.TypeNS,
		Class: dnsmessage.ClassINET,
	}
	rootServers := strings.Split(ROOT_SERVERS, ",")
	if len(rootServers) == 0 {
		t.Fatalf("No root servers found")
	}
	servers := []net.IP{net.ParseIP(rootServers[0])}
	dnsAnswer, header, err := outgoingDnsQuery(servers, question)
	if err != nil {
		t.Fatalf("outgoingDnsQuery ERROR: %s", err)
	}
	if header == nil {
		t.Fatalf("No header found")
	}
	if dnsAnswer == nil {
		t.Fatalf("No dnsAnswer found")
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("Response was not successful, maybe DNS server has changed?")
	}
	err = dnsAnswer.SkipAllAnswers()
	if err != nil {
		t.Fatalf("SkipAllAnswers ERROR: %s", err)
	}
	parseAuthorities, err := dnsAnswer.AllAuthorities()
	if err != nil {
		t.Fatalf("Error getting the Answers")
	}
	if len(parseAuthorities) == 0 {
		t.Fatalf("No answers received")
	}
}
