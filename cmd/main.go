package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	bencoder "github.com/codescalersinternships/bencode-nabil/pkg"
)

type TorrentPeers struct {
	Interval int
	Peers    string
}
type Info struct {
	length      int64
	name        string
	pieceLength int64
	pieces      string
}
type TorrentFile struct {
	announce string
	info     Info
	hash     []byte
}

// type TrackerRequest struct {
// 	URL        string
// 	InfoHash   string
// 	PeerID     string
// 	Port       int
// 	Uploaded   int
// 	Downloaded int
// 	Left       int
// 	Compact    int
// }
// type TrackerResponse struct {
// 	Interval int   
// 	Peers    string 
// }
type Handshake struct {
	length byte
	pstr   string
	resv   [8]byte
	info   []byte
	peerId []byte
}


func calculateSHA1(input []byte) []byte {
	sha1Hash := sha1.New()
	sha1Hash.Write(input)
	return sha1Hash.Sum(nil)
}

func newTorrentFile(filename string) TorrentFile {
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
		length: infoInterface["length"].(int64),
		name:infoInterface["name"].(string),
		pieceLength:infoInterface["piece length"].(int64),
		pieces: infoInterface["pieces"].(string),
	}
	en, err := bencoder.Encoder(infoInterface)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	return TorrentFile{
		announce: d.(map[interface{}]interface{})["announce"].(string),
		info: newInfo,
		hash: calculateSHA1(en),
	}
}

// parsePeers decodes the compact peer list
func parsePeers(peers string) ([]string, error) {
	var result []string
	peerBytes := []byte(peers)

	if len(peerBytes)%6 != 0 {
		return nil, fmt.Errorf("peer bytes length is not a multiple of 6")
	}

	for i := 0; i < len(peerBytes); i += 6 {
		ip := net.IP(peerBytes[i : i+4]) // first 4 bytes are IP
		port := binary.BigEndian.Uint16(peerBytes[i+4 : i+6]) // last 2 bytes are port
		result = append(result, fmt.Sprintf("%s:%d", ip, port))
	}
	return result, nil
}


func peers(torrent TorrentFile) ([] string, error) {
	params := url.Values{}
	params.Add("info_hash", string(torrent.hash))
	params.Add("peer_id", "00112233445566778899")
	params.Add("port", "6881")
	params.Add("uploaded", "0")
	params.Add("downloaded", "0")
	params.Add("left", strconv.FormatInt(torrent.info.length, 10))
	params.Add("compact", "1")
	// Construct the final URL with query parameters
	finalURL := fmt.Sprintf("%s?%s", torrent.announce, params.Encode())
	// Making the GET request
	response, err := http.Get(finalURL)
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
	if peers, ok := decoded.(map[interface{}]interface{})["peers"].(string); ok {
		parsedPeers, err := parsePeers(peers)
		if err != nil {
			return nil, fmt.Errorf("error parsing peers: %v", err)
		}
		fmt.Println("Peers:", parsedPeers)
		return parsedPeers, nil
	} else {
		fmt.Println("No peers found")
		return []string{}, nil
	}
}

func establishTCPCon(torrent TorrentFile, peerAddress string) (net.Conn, Handshake ,error){
	conn, err := net.Dial("tcp", peerAddress)
	if err != nil {
		return nil, Handshake{}, fmt.Errorf("failed to start tcp connection: %e", err)
	}
	pstrlen := byte(19) // The length of the string "BitTorrent protocol"
	pstr := []byte("BitTorrent protocol")
	reserved := make([]byte, 8) // Eight zeros
	handshake := append([]byte{pstrlen}, pstr...)
	handshake = append(handshake, reserved...)
	handshake = append(handshake, torrent.hash...)
	handshake = append(handshake, []byte{0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9}...)
	conn.Write(handshake)
	buf := make([]byte, 68)
	_, err = conn.Read(buf)
	if err != nil {
		conn.Close();
		return nil, Handshake{}, fmt.Errorf("failed to read connection response: %e", err)
	}
	fmt.Printf("Peer ID: %s\n", hex.EncodeToString(buf[48:]))
	return conn, Handshake{
		length: buf[0],
		pstr:   string(buf[1:20]),
		resv:   [8]byte{},
		info:   buf[28:48],
		peerId: buf[48:68],
	}, nil
}

func handleHandshake( conn net.Conn) error {
	buf := make([]byte, 68)
	_, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("hendlehand shake err: %e", err)
	}
	fmt.Printf("Received: %x\n", buf)
	if buf[4] != 0x05 { // Bitfield message ID is 5
		return fmt.Errorf("hendlehand shake err id isn't 5 but %v", buf[4])
	}
	return nil
}


func sendInterestedMessage(conn net.Conn) error {
	interestedMsg := []byte{0, 0, 0, 1, 0x02}
	_, err := conn.Write(interestedMsg)
	return err
}

func handleBitfieldMessage(conn net.Conn) error {
	buf := make([]byte, 5)
	_, err := conn.Read(buf)
	if err != nil {
		return err
	}
	messageCode := buf[4]
	if messageCode == 0x05 {
		fmt.Print("Receive bitfield msg\n")
		payloadBuffer := new(bytes.Buffer)
		binary.Write(payloadBuffer, binary.BigEndian, uint32(2))
		payloadBytes := payloadBuffer.Bytes()
		conn.Write(payloadBytes)
	}
	return nil
}

func handleUnchokeMessage(conn net.Conn) error {
	buf := make([]byte, 5)  // expected a 5-byte message: 4-byte length + 1-byte Unchoke
	_, err := conn.Read(buf)
	if err != nil {
		return err
	}

	if buf[4] != 0x01 {
		fmt.Println("recieved unchoke")
	}
	return nil
}

func downloadPieceBlocks(conn net.Conn, pieceIndex, pieceLength int64) ([]byte, error) {
	const pieceBlockMaxSize = 1<<14
	pieceBlocksAmount := pieceLength / pieceBlockMaxSize
	if pieceLength%pieceBlockMaxSize > 0 {
		pieceBlocksAmount++
	}
	intPieceLength := int(pieceLength)
	piece := make([]byte, pieceLength)
	for i := 0; i < intPieceLength; i += pieceBlockMaxSize {
		pieceBlockLength := pieceBlockMaxSize
		if i+pieceBlockMaxSize > intPieceLength {
			pieceBlockLength = intPieceLength - i
		}
		requestPayload := buildRequestPayload(int(pieceIndex), i, pieceBlockLength)
		fmt.Printf("%v\n", requestPayload)
		conn.Write(requestPayload)
		fmt.Printf("Begin: %d, length: %d, piece length: %d, blocks amount: %d\n", i, pieceBlockLength, pieceLength, pieceBlocksAmount)
		err := handleBlockResponse(conn, piece)
		if err != nil {
			return nil, err
		}
	}
	return piece, nil
}

func buildRequestPayload(pieceIndex, begin, length int) []byte {
	payloadBuffer := new(bytes.Buffer)
	binary.Write(payloadBuffer, binary.BigEndian, uint32(13))
	payload := payloadBuffer.Bytes()
	payload = append(payload, 6)
	payloadBuffer = new(bytes.Buffer)
	binary.Write(payloadBuffer, binary.BigEndian, uint32(pieceIndex))
	payload = append(payload, payloadBuffer.Bytes()...)
	payloadBuffer = new(bytes.Buffer)
	binary.Write(payloadBuffer, binary.BigEndian, uint32(begin))
	payload = append(payload, payloadBuffer.Bytes()...)
	payloadBuffer = new(bytes.Buffer)
	binary.Write(payloadBuffer, binary.BigEndian, uint32(length))
	payload = append(payload, payloadBuffer.Bytes()...)
	return payload
}

func handleBlockResponse(conn net.Conn, piece []byte) error {
	var messageLength uint32
	var messageId uint8
	err := binary.Read(conn, binary.BigEndian, &messageLength)
	if err != nil {
		if err.Error() == "EOF" {
			return nil
		}
	}
	err = binary.Read(conn, binary.BigEndian, &messageId)
	if err != nil {
		return fmt.Errorf("cannot read message ID, %s", err.Error())
	}
	if messageLength > 0 {
		buf := make([]byte, messageLength-1)
		_, err = io.ReadAtLeast(conn, buf, len(buf))
		if err != nil {
			return fmt.Errorf("cannot read payload, %s", err.Error())
		}
		blockBegin := binary.BigEndian.Uint32(buf[4:8])
		block := buf[8:]
		copy(piece[blockBegin:], block)
	}
	return nil
}


func downloadPiece(torrent TorrentFile, peerAddr string, pieceIndex int) ([]byte, int64, error) {
	conn, _, err := establishTCPCon(torrent, peerAddr)
	if err != nil {
		return nil, 0, err
	}

	defer conn.Close()
	
	err = handleHandshake(conn)
	if err != nil {
		return nil, 0, err
	}
	fmt.Println("Received bitfield message")
	// Send interested message
	err = sendInterestedMessage(conn)
	if err != nil {
		return nil, 0, err
	}
	// Now wait for the unchoke message (ID = 1)
	err = handleBitfieldMessage(conn)
	if err != nil {
		return nil, 0, err
	}

	// Now wait for the unchoke message (ID = 1)
	err = handleUnchokeMessage(conn)
	if err != nil {
		return nil, 0, err
	}
	
	//Each piece's hash is represented as a 20-byte string
	piecesAmount := len(torrent.info.pieces) / 20
	pieceLength := torrent.info.pieceLength
	fileLength := torrent.info.length
	//Adjusts the length of the last piece if it’s smaller than the standard piece length
	if pieceIndex == piecesAmount-1 {
		pieceLength = fileLength - pieceLength*(int64(piecesAmount)-1)
	}
	piece, err := downloadPieceBlocks(conn, int64(pieceIndex), pieceLength)
	if err != nil {
		return nil, 0, err
	}
	return piece, pieceLength, nil
	
	
	
	
	// // Requesting the first block of the first piece
	// index := 0
	// begin := uint32(0)
	// length := uint32(16 * 1024)  // 16 KB

	// requestMsg := []byte{
	// 	0, 0, 0, 13, // Length (13 bytes)
	// 	0, 0, 0, 6,  // Request message ID (6)
	// 	byte(index), byte(index >> 8), byte(index >> 16), byte(index >> 24),  // Index (4 bytes)
	// 	byte(begin), byte(begin >> 8), byte(begin >> 16), byte(begin >> 24),  // Begin (4 bytes)
	// 	byte(length), byte(length >> 8), byte(length >> 16), byte(length >> 24),  // Length (4 bytes)
	// }
	// _, err = conn.Write(requestMsg)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// buf = make([]byte, 16 * 1024)  // Buffer for 16 KB block
	// _, err = conn.Read(buf)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// // Process the received data (e.g., write it to a file)
	// fmt.Printf("Received block for piece %d at offset %d\n", buf[0], buf[1])
	// return nil, 0, nil
}

func handleDownload(torrent TorrentFile, peerAddr string, outputFilePath string) error{
	wholePieceLength := torrent.info.pieceLength
	fileLength := torrent.info.length
	fileBytes := make([]byte, fileLength)
	piecesAmount := len(torrent.info.pieces) / 20
	pieces := make([][]byte, piecesAmount)
	for i := range pieces {
		piece, pieceLength, err := downloadPiece(torrent, peerAddr, i)
		if err != nil {
			return err
		}
		copy(fileBytes[i*int(wholePieceLength):i*int(wholePieceLength)+int(pieceLength)], piece)
	}
	os.WriteFile(outputFilePath, fileBytes, os.ModePerm)
	fmt.Printf("Downloaded to %s.\n", outputFilePath)
	return nil
}

func main() {
	command := os.Args[1]
	switch command {
	case "decode":
		x, err := bencoder.Decoder(os.Args[2])
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		y, err := json.Marshal(x)
		if err != nil {
			fmt.Printf("error: encode to json%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", y)
	case "info":
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Printf("error: read file: %v\n", err)
			os.Exit(1)
		}
		d, err := bencoder.Decoder(string(data))
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Tracker URL: %v\n", d.(map[interface{}]interface{})["announce"])
		info, ok := d.(map[interface{}]interface{})["info"].(map[interface{}]interface{})
		if info == nil || !ok {
			fmt.Printf("No info section\n")
			return
		}
		fmt.Printf("Length: %v\n", info["length"])
		h := sha1.New()
		en,err := bencoder.Encoder(d.(map[interface{}]interface{})["info"])
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		h.Sum(en)
		fmt.Println(string(en))
		fmt.Printf("Info Hash: %x\n", h.Sum(nil))
		fmt.Printf("Length: %v\n", info["piece length"])
		h = sha1.New()
		en,err = bencoder.Encoder(info["pieces"])
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		h.Sum(en)
		fmt.Printf("Piece Hashes: %x\n", info["pieces"])
	case "peers":
		torrent := newTorrentFile(os.Args[2])
		_, err := peers(torrent)
		if err != nil {
			panic(fmt.Sprintf("error while getting peers: %e", err))
		}
		
	case "hanshake":
		torrent := newTorrentFile(os.Args[2])
		peerAddress := os.Args[3]
		conn,_,_ := establishTCPCon(torrent, peerAddress)
		conn.Close()
	case "download_piece":
		torrent := newTorrentFile(os.Args[2])
		peersFound, err := peers(torrent)
		if err != nil {
			panic(fmt.Sprintf("error while getting peers: %e", err))
		}
		piece, _, _:= downloadPiece(torrent, peersFound[0], 0)
		
		outputFilePath := os.Args[3]
		fmt.Println("Writing file")
		os.WriteFile(outputFilePath, piece, os.ModePerm)
		fmt.Printf("Piece %d downloaded to %s.", 0, outputFilePath)
	case "download":
		torrent := newTorrentFile(os.Args[2])
		outputFilePath := os.Args[3]
		peersFound, err := peers(torrent)
		if err != nil {
			panic(fmt.Sprintf("error while getting peers: %e", err))
		}
		handleDownload(torrent, peersFound[0], outputFilePath)
		
	default:
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}