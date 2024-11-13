package torrentfile

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"main/p2p"
	"os"

	bencoder "github.com/codescalersinternships/bencode-nabil/pkg"
)


type TorrentFile struct {
	Announce string
	Info     Info
	Hash     []byte
	PeiceHashs [][20]byte
}

type Info struct {
	Length      int64
	Name        string
	PieceLength int64
	Pieces      string
}


// DownloadToFile downloads a torrent and writes it to a file
func (t *TorrentFile) DownloadToFile(path string) error {
	var peerID [20]byte
	_, err := rand.Read(peerID[:])
	if err != nil {
		return err
	}

	peers, err := t.getPeers(peerID, 6881)
	if err != nil {
		return err
	}

	torrent := p2p.Torrent{
		Peers:       peers,
		PeerID:      peerID,
		InfoHash:    [20]byte(t.Hash),
		PieceHashes: t.PeiceHashs,
		PieceLength: int(t.Info.PieceLength),
		Length:      int(t.Info.Length),
		Name:        t.Info.Name,
	}
	buf, err := torrent.Download()
	if err != nil {
		return err
	}

	outFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer outFile.Close()
	_, err = outFile.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

func splitPieceHashes(torrentInfo Info) ([][20]byte, error) {
	hashLen := 20 // Length of SHA-1 hash
	buf := []byte(torrentInfo.Pieces)
	if len(buf)%hashLen != 0 {
		err := fmt.Errorf("Received malformed Pieces of length %d", len(buf))
		return nil, err
	}
	numHashes := len(buf) / hashLen
	hashes := make([][20]byte, numHashes)

	for i := 0; i < numHashes; i++ {
		copy(hashes[i][:], buf[i*hashLen:(i+1)*hashLen])
	}
	return hashes, nil
}



func calculateSHA1(input []byte) []byte {
	sha1Hash := sha1.New()
	sha1Hash.Write(input)
	return sha1Hash.Sum(nil)
}

func NewTorrentFile(filename string) (TorrentFile, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("error: read file: %v\n", err)
		os.Exit(1)
	}
	d, err := bencoder.Decoder(string(data))
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	infoInterface:= d.(map[interface{}]interface{})["info"].(map[interface{}]interface{})
	newInfo := Info{
		Length: infoInterface["length"].(int64),
		Name:infoInterface["name"].(string),
		PieceLength:infoInterface["piece length"].(int64),
		Pieces: infoInterface["pieces"].(string),
	}
	en, err := bencoder.Encoder(infoInterface)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}

	pieceHashes, err := splitPieceHashes(newInfo)
	if err != nil {
		return TorrentFile{}, err
	}
	return TorrentFile{
		Announce: d.(map[interface{}]interface{})["announce"].(string),
		Info: newInfo,
		Hash: calculateSHA1(en),
		PeiceHashs: pieceHashes,
	}, nil
}