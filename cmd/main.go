package main

import (
	"fmt"
	"log"
	"os"

	"github.com/codescalersinternships/bittorrent-nabil/tree/development/torrentfile"
)



func main() {
	command := os.Args[1]
	switch command {
	case "download":
		inPath := os.Args[2]
		outPath := os.Args[3]

		tf, err := torrentfile.NewTorrentFile(inPath)
		if err != nil {
			log.Fatal(err)
		}

		err = tf.DownloadToFile(outPath)
		if err != nil {
			log.Fatal(err)
		}
		
	default:
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}