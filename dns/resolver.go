package dns

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const ROOT_SERVERS = "198.41.0.4,170.247.170.2,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53,192.36.148.17,192.58.128.30,193.0.14.129,199.7.83.42,202.12.27.33"

func HandlePacket(pc net.PacketConn, addr net.Addr, buffer []byte) {
	if err := handlePacket(pc, addr, buffer); err != nil {
		fmt.Printf("handlePacket error [%s]: %s\n", addr.String(), err)
	}
}

func handlePacket(pc net.PacketConn, addr net.Addr, buffer []byte) error {
	p := dnsmessage.Parser{}
	header, err := p.Start(buffer)
	if err != nil {
		return err
	}

	question, err := p.Question()
	if err != nil {
		return err
	}

	res, err := dnsQuery(getRootServers(), question)
	if err != nil {
		return err
	}

	res.Header.ID = header.ID
	resBuffer, err := res.Pack()
	if err != nil {
		return err
	}

	_, err = pc.WriteTo(resBuffer, addr)
	if err != nil {
		return err
	}

	return nil
}

func dnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Message, error) {
	fmt.Printf("Question: %v\n", question)
	for i := 0; i < 3; i++ {
		dnsAnswer, header, err := outgoingDnsQuery(servers, question)
		if err != nil {
			return nil, err
		}
		parsedAnswers, err := dnsAnswer.AllAnswers()
		if err != nil {
			return nil, err
		}

		if header.Authoritative {
			return &dnsmessage.Message{
				Header:  dnsmessage.Header{Response: true},
				Answers: parsedAnswers,
			}, nil
		}
		authorities, err := dnsAnswer.AllAuthorities()
		if err != nil {
			return nil, err
		}

		if len(authorities) == 0 {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{
					RCode: dnsmessage.RCodeNameError,
				},
			}, nil
		}
		nameservers := make([]string, len(authorities))
		for k, auth := range authorities {
			if auth.Header.Type == dnsmessage.TypeNS {
				nameservers[k] = auth.Body.(*dnsmessage.NSResource).NS.String()
			}
		}
		fmt.Printf("servers: %+v\n", nameservers)
		additionals, err := dnsAnswer.AllAdditionals()
		if err != nil {
			return nil, err
		}

		newResolverServersFound := false
		servers = []net.IP{}
		for _, additional := range additionals {
			if additional.Header.Type == dnsmessage.TypeA {
				for _, ns := range nameservers {
					if additional.Header.Name.String() == ns {
						newResolverServersFound = true
						servers = append(servers, additional.Body.(*dnsmessage.AResource).A[:])
					}
				}
			}
		}

		if !newResolverServersFound {
			for _, ns := range nameservers {
				if !newResolverServersFound {
					q := dnsmessage.Question{
						Name:  dnsmessage.MustNewName(ns),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					}
					res, err := dnsQuery(getRootServers(), q)
					if err != nil {
						fmt.Printf("Warning: lookup of nameserver %s failed: %s\n", ns, err)
					} else {
						newResolverServersFound = true
						for _, ans := range res.Answers {
							if ans.Header.Type == dnsmessage.TypeA {
								servers = append(servers, ans.Body.(*dnsmessage.AResource).A[:])
							}
						}
					}
				}
			}
		}
	}
	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			RCode: dnsmessage.RCodeServerFailure,
		},
	}, nil
}

func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
	fmt.Printf("New outgoing DNS query for %s, servers: %+v\n", question.Name.String(), servers)
	max := ^uint16(0)
	rn, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return nil, nil, err
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       uint16(rn.Int64()),
			Response: false,
			OpCode:   dnsmessage.OpCode(0),
		},
		Questions: []dnsmessage.Question{question},
	}
	buff, err := msg.Pack()
	if err != nil {
		return nil, nil, err
	}

	var conn net.Conn
	for _, server := range servers {
		conn, err = net.Dial("udp", server.String()+":53")
		if err == nil {
			break
		}
	}
	if conn == nil {
		return nil, nil, fmt.Errorf("Failed to stablish connection with the servers: %s", err)
	}

	_, err = conn.Write(buff)
	if err != nil {
		return nil, nil, err
	}

	answer := make([]byte, 512)
	n, err := bufio.NewReader(conn).Read(answer)
	if err != nil {
		return nil, nil, err
	}

	err = conn.Close()
	if err != nil {
		return nil, nil, err
	}

	p := dnsmessage.Parser{}
	header, err := p.Start(answer[:n])
	if conn == nil {
		return nil, nil, fmt.Errorf("Parser start error: %s", err)
	}

	questions, err := p.AllQuestions()
	if err != nil {
		return nil, nil, err
	}
	if len(questions) != len(msg.Questions) {
		return nil, nil, fmt.Errorf("Answer packet does not have the same amouunt of questions")
	}

	err = p.SkipAllQuestions()
	if err != nil {
		return nil, nil, err
	}

	return &p, &header, nil
}

func getRootServers() []net.IP {
	rootServers := []net.IP{}
	for _, rs := range strings.Split(ROOT_SERVERS, ",") {
		ip := net.ParseIP(rs)
		if ip != nil {
			rootServers = append(rootServers, ip)
		} else {
			fmt.Printf("Error parsing IP address of: %s server\n", rs)
		}
	}
	return rootServers
}
