package torrentfile

import (
	"fmt"
	"io"
	"main/peers"
	"net/http"
	"net/url"
	"strconv"
	"time"

	bencoder "github.com/codescalersinternships/bencode-nabil/pkg"
)


func (t *TorrentFile) BuildTrackerURL(peerID [20]byte, port uint16) (string, error) {
	base, err := url.Parse(t.Announce)
	if err != nil {
		return "", err
	}
	params := url.Values{}
	params.Add("info_hash", string(t.Hash))
	params.Add("peer_id", "00112233445566778899")
	params.Add("port", "6881")
	params.Add("uploaded", "0")
	params.Add("downloaded", "0")
	params.Add("left", strconv.FormatInt(t.Info.Length, 10))
	params.Add("compact", "1")
	base.RawQuery = params.Encode()
	return base.String(), nil
}


func (torrent *TorrentFile)getPeers(peerID [20]byte, port uint16) ([]peers.Peer, error) {
	finalURL, err := torrent.BuildTrackerURL(peerID, port)
	if err != nil {
		return nil, err
	}

	c := &http.Client{Timeout: 15 * time.Second}
	response, err := c.Get(finalURL)
	if err != nil {
		return nil, fmt.Errorf("error sending get request: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	// Decode the response
	decoded, err := bencoder.Decoder(string(body))
	if err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	// Extract and parse peers
	if infoPeers, ok := decoded.(map[interface{}]interface{})["peers"].(string); ok {
		parsedPeers, err := peers.ParsePeers(infoPeers)
		if err != nil {
			return nil, fmt.Errorf("error parsing peers: %v", err)
		}
		fmt.Println("Peers:", parsedPeers)
		return parsedPeers, nil
	} else {
		fmt.Println("No peers found")
		return []peers.Peer{}, nil
	}
}