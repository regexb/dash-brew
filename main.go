package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
)

type Button struct {
	Name string                 `json:"name"`
	Mac  string                 `json:"mac"`
	Url  string                 `json:"url"`
	Data map[string]interface{} `json:"data"`
}

type Configuration struct {
	Buttons []Button `json:"buttons"`
	Nic     string   `json:"nic"`
}

func loadConfig() Configuration {
	file, _ := os.Open("configuration.json")
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("Failed to parse configuration:", err)
	}
	fmt.Println(configuration.Buttons)
	return configuration
}

func makeRequest(url string, data map[string]interface{}) {
	postData, err := json.Marshal(data)
	if err != nil {
		log.Fatal(err)
	}
	res, err := http.Post(url, "application/json", bytes.NewBuffer([]byte(postData)))
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("HTTP Response: %s\n", body)
}

func main() {

	var configuration = loadConfig()

	log.Printf("Starting up on interface[%v]...", configuration.Nic)

	h, err := pcap.OpenLive(configuration.Nic, 65536, true, pcap.BlockForever)

	if err != nil || h == nil {
		log.Fatalf("Error opening interface: %s\n You probably need to run as root?\n", err)
	}
	defer h.Close()

	var filter = "arp and ("
	for _, button := range configuration.Buttons {
		mac, err := net.ParseMAC(button.Mac)
		if err != nil {
			log.Fatal(err)
		}
		filter += "(ether src host " + mac.String() + ")"
	}
	filter += ")"

	err = h.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Unable to set filter! %s\n", err)
	}
	log.Println("Listening for Dash buttons...")

	packetSource := gopacket.NewPacketSource(h, h.LinkType())

	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		for _, button := range configuration.Buttons {
			mac, err := net.ParseMAC(button.Mac)
			if err != nil {
				log.Fatal(err)
			}
			if bytes.Equal(ethernetPacket.SrcMAC, mac) {
				log.Printf("Button [%v] was pressed.", button.Name)
				makeRequest(button.Url, button.Data)
			} else {
				log.Printf("Received button press, but don't know how to handle MAC[%v]", ethernetPacket.SrcMAC)
			}
		}
	}

}
