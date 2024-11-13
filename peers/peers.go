package peers

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// Peer encodes connection information for a peer
type Peer struct {
    IP   net.IP
    Port uint16
}

// parsePeers decodes the compact peer list
func ParsePeers(peers string) ([]Peer, error) {
	var result []Peer
	peerBytes := []byte(peers)

	if len(peerBytes)%6 != 0 {
		return nil, fmt.Errorf("peer bytes length is not a multiple of 6")
	}

	for i := 0; i < len(peerBytes); i += 6 {
		peer := Peer{
			IP: net.IP(peerBytes[i : i+4]), // first 4 bytes are IP
			Port: binary.BigEndian.Uint16(peerBytes[i+4 : i+6]), // last 2 bytes are port
		}
		result = append(result, peer)
	}
	return result, nil
}


func (p Peer) String() string {
	return net.JoinHostPort(p.IP.String(), strconv.Itoa(int(p.Port)))
}