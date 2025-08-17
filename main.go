package main

import (
	"CTLogchecker/ClientApp/datastruct"
	"CTLogchecker/ClientApp/services"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"strconv"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func main() {
	// client takes argument from command line:
	// server address
	// whether participate in reveal 0 for no, 1 for yes

	args := os.Args[1:] // Skip the program path at os.Args[0]

	participate_in_reveal, err := strconv.Atoi(args[1])

	if err != nil {
		panic(err)
	}

	participate_in_reveal_boolean := true
	if participate_in_reveal == 0 {
		participate_in_reveal_boolean = false
	}

	server_address := args[0]
	collector_address := args[2]
	shuffler_under_k_keys, err := strconv.Atoi(args[3])
	if err != nil {
		panic(err)
	}
	curve := ecdh.P256()
	network_interface, err := rpc.DialHTTP("tcp", server_address)
	if err != nil {
		log.Fatal("dialing:", err)
	}

	client := services.NewClient(curve)

	// get my ip
	response, err := http.Get("https://api.ipify.org")
	if err != nil {
		fmt.Println("Error fetching IP: ", err)
		return
	}
	defer response.Body.Close()

	ip, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Error reading response: ", err)
		return
	}

	fmt.Println("Client IP address:", string(ip))
	client.MyIP = string(ip)
	// fmt.Println(client.ReportingValue)
	client.Shamir_curve = curves.P256()
	client.ShuffleUnderKeys = shuffler_under_k_keys

	stats := datastruct.ClientStats{
		Entry: client.ReportingValue,
	}
	// Synchronous call
	req := datastruct.RegistrationRequest{
		H_shuffle: client.H_shuffle,
		G_shuffle: client.G_shuffle,
		DH_Pub_H:  client.DH_Pub_H,
		IP:        client.MyIP,
	}
	var reply datastruct.RegistrationResponse
	// var reply int

	register_successful := false

	dial := func() *rpc.Client {
		c, err := rpc.Dial("tcp", server_address)
		if err != nil {
			log.Printf("dial to %s failed: %v", server_address, err)
			return nil
		}
		return c
	}

	for !register_successful {
		// ensure we have a live client
		if network_interface == nil {
			network_interface = dial()
			if network_interface == nil { // couldn't connect; retry immediately
				continue
			}
		}

		timeout := 30 * time.Second

		done := make(chan *rpc.Call, 1)
		call := network_interface.Go("CTLogCheckerAuditor.RegisterClient", req, &reply, done)

		select {
		case res := <-call.Done:
			if res.Error == nil {
				if reply.Status {
					log.Printf("Registering OK")
					register_successful = true
				} else {
					log.Printf("Registering responded but not accepted (Status=false); retrying")
					// immediate retry with same connection
				}
			} else if errors.Is(res.Error, rpc.ErrShutdown) {
				log.Printf("Registering failed: connection is shut down; redialing %s", server_address)
				_ = network_interface.Close()
				network_interface = nil // force redial next iteration
			} else {
				log.Printf("Registering failed: %v (retrying)", res.Error)
				// immediate retry with same connection
			}

		case <-time.After(timeout):
			log.Printf("Registering timed out after %s; redialing %s", timeout, server_address)
			_ = network_interface.Close() // aborts in-flight call (it will finish with ErrShutdown internally)
			network_interface = nil       // force redial next iteration
		}
	}

	// err = network_interface.Call("CTLogCheckerAuditor.RegisterClient", req, &reply)
	// if err != nil {
	// 	log.Fatal("arith error:", err)
	// }
	// fmt.Println(reply.AssignedID)
	client.ID = reply.AssignedID
	stats.ClientID = client.ID
	client.RevealThreshold = reply.RevealThreshold
	client.TotalClients = reply.TotalClients
	start := time.Now() // Start the timer
	i_entry, err := services.CreateInitialEntry(client)
	elapsed := time.Since(start) // Calculate elapsed time
	elapsedSeconds := elapsed.Seconds()
	// fmt.Println("Initial Reporting", elapsedSeconds)
	stats.InitalReportingTime = elapsedSeconds
	if err != nil {
		log.Fatal("arith error:", err)
	}
	init_report_req := datastruct.InitalReportingRequest{
		ShufflerID:   client.ID,
		InitialEntry: *i_entry,
	}
	// record upload data
	report_data_up, err := json.Marshal(init_report_req)

	if err != nil {
		log.Fatalf("Error serializing to JSON: %v", err)
	}
	stats.UploadBytesInitalReporting = len(report_data_up)
	/// report the initial entry
	var init_report_reply datastruct.InitalReportingReply
	report_s := false
	var Shuffle_PubKeys []*datastruct.ShufflePubKeys
	for !report_s {
		err = network_interface.Call("CTLogCheckerAuditor.ReportInitialEntry", init_report_req, &init_report_reply)
		if err != nil {
			log.Fatal("arith error:", err)
		}
		if init_report_reply.Status {
			report_s = true
			Shuffle_PubKeys = init_report_reply.Shuffle_PubKeys
		}
	}

	report_data_down, err := json.Marshal(init_report_reply)
	if err != nil {
		log.Fatalf("Error serializing to JSON: %v", err)
	}
	stats.DownloadBytesInitalReporting = len(report_data_down)

	// ReportInitialEntrySecreteShare
	if len(Shuffle_PubKeys) != int(client.TotalClients) {
		log.Fatal("arith error: not enough keys")
	}

	// generate secrete shares
	secrete_share_start := time.Now() // Start the timer

	pieces, err := services.SecreteShare(client, Shuffle_PubKeys)

	secrete_share_elapsed := time.Since(secrete_share_start) // Calculate elapsed time
	secrete_share_elapsedSeconds := secrete_share_elapsed.Seconds()
	stats.SecreteShareTime = secrete_share_elapsedSeconds

	if err != nil {
		log.Fatal("arith error:", err)
	}
	// report the secrete shares
	init_report_secrete_req := datastruct.InitalReportingSecreteSharingRequest{
		ShufflerID:    client.ID,
		SecretePieces: pieces,
	}

	var init_report_secrete_reply datastruct.InitalReportingSecreteSharingReply
	init_report_secrete_up, err := json.Marshal(init_report_secrete_req)
	if err != nil {
		log.Fatalf("Error serializing to JSON: %v", err)
	}
	stats.UploadBytesSecreteShare = len(init_report_secrete_up)

	report_s_secrete := false
	for !report_s_secrete {
		err = network_interface.Call("CTLogCheckerAuditor.ReportInitialEntrySecreteShare", init_report_secrete_req, &init_report_secrete_reply)
		if err != nil {
			log.Fatal("arith error:", err)
		}
		if init_report_secrete_reply.Status {
			report_s_secrete = true
		}
	}

	init_report_secrete_down, err := json.Marshal(init_report_secrete_reply)
	if err != nil {
		log.Fatalf("Error serializing to JSON: %v", err)
	}
	stats.DownloadBytesSecreteShare = len(init_report_secrete_down)

	/// perform the shuffle
	/// acquire the lock and download the database

	rpc.Register(client)

	shuffle_completed := false
	fmt.Println("Starting Shuffle Phase for client ", client.ID)
	for !shuffle_completed {
		AcceptReq()
		if client.ShuffleTime > 0 {
			shuffle_completed = true
		} else {
			fmt.Println("accepted a request to shuffle but somehow failed ", client.ID)
		}
	}

	fmt.Println("Finished Shuffling")

	if participate_in_reveal_boolean {
		// perform reveal
		reveal_lock := false

		reveal_req := datastruct.RevealPhaseAcquireDatabaseRequest{
			ShufflerID: client.ID,
		}

		var reveal_reply datastruct.RevealPhaseAcquireDatabaseReply

		for !reveal_lock {
			err := network_interface.Call("CTLogCheckerAuditor.RevealPhaseClientAcquireDatabase", reveal_req, &reveal_reply)
			if err != nil {
				log.Fatal("reveal error:", err)
			}
			if reveal_reply.Status {
				reveal_lock = true
			}
		}

		reveal_down, err := json.Marshal(reveal_reply)
		if err != nil {
			log.Fatalf("Error serializing to JSON: %v", err)
		}
		stats.DownloadBytesReveal += len(reveal_down)

		// perform reveal
		reveal_start := time.Now()

		reveal_res_req, err := services.ClientReveal(client, reveal_reply.Database, reveal_reply.ZK_info, reveal_reply.AuditorZKInfo)

		reveal_elapsed := time.Since(reveal_start) // Calculate elapsed time
		reveal_elapsedSeconds := reveal_elapsed.Seconds()
		stats.RevealTime = reveal_elapsedSeconds

		if err != nil {
			log.Fatal("reveal error:", err)
		}

		reveal_res_req_up, err := json.Marshal(reveal_res_req)
		if err != nil {
			log.Fatalf("Error serializing to JSON: %v", err)
		}
		stats.UploadBytesReveal += len(reveal_res_req_up)

		var reveal_res_reply datastruct.RevealPhaseReportRevealReply

		for true {
			err := network_interface.Call("CTLogCheckerAuditor.RevealPhaseClientRevealResult", reveal_res_req, &reveal_res_reply)
			if err != nil {
				log.Fatal("reveal error:", err)
			}
			if reveal_res_reply.Status {
				fmt.Println("Reveal Successful ", client.ID)
				break
			}
		}

		// perform fault tolerance
		ft_req := datastruct.FaultTolerancePhaseAcquireDatabaseRequest{
			ShufflerID: client.ID,
		}

		var ft_reply datastruct.FaultTolerancePhaseAcquireDatabaseReply
		for true {
			err := network_interface.Call("CTLogCheckerAuditor.FaultTolerancePhaseAcquireDatabase", ft_req, &ft_reply)
			if err != nil {
				log.Fatal("reveal error:", err)
			}
			if ft_reply.Status {
				break
			}
		}

		ft_reply_down, err := json.Marshal(ft_reply)
		if err != nil {
			log.Fatalf("Error serializing to JSON: %v", err)
		}
		stats.DownloadBytesFT += len(ft_reply_down)

		if ft_reply.FTNeeded {
			// submit ft entries
			ft_submit_req := datastruct.FaultTolerancePhaseReportResultRequest{
				ShufflerID:      client.ID,
				DecryptedPieces: []datastruct.SecreteShareDecrypt{},
			}

			ft_start := time.Now()

			for i := 0; i < len(ft_reply.AbsentClients); i++ {
				ft_piece, err := services.ClientReportDecryptedSecret(client, ft_reply.AbsentClients[i], ft_reply.Database)
				if err != nil {
					panic(err)
				}
				ft_submit_req.DecryptedPieces = append(ft_submit_req.DecryptedPieces, *ft_piece)
			}

			ft_elapsed := time.Since(ft_start) // Calculate elapsed time
			ft_elapsedSeconds := ft_elapsed.Seconds()
			stats.FTTime = ft_elapsedSeconds

			var ft_submit_reply datastruct.FaultTolerancePhaseReportResultReply

			for true {
				err := network_interface.Call("CTLogCheckerAuditor.FaultTolerancePhaseReportResult", ft_submit_req, &ft_submit_reply)
				if err != nil {
					log.Fatal("reveal error:", err)
				}
				if ft_submit_reply.Status {
					break
				}
			}

			ft_submit_req_up, err := json.Marshal(ft_submit_req)
			if err != nil {
				log.Fatalf("Error serializing to JSON: %v", err)
			}
			stats.UploadBytesFT += len(ft_submit_req_up)
		}

	}

	if participate_in_reveal_boolean {
		fmt.Print("Client ", client.ID, " protocol completed with reveal\n")
	} else {
		fmt.Print("Client ", client.ID, " protocol completed without reveal\n")
	}

	// fmt.Println(stats)
	stats.ShuffleTime = client.ShuffleTime
	stats.DownloadBytesShuffle = client.ShuffleDownload
	stats.UploadBytesShuffle = client.ShuffleUpload
	stats.AuditorZKCheckTime = client.AuditorZKCheckTime

	// report the stats to the collector
	collector_interface, err := rpc.DialHTTP("tcp", collector_address)

	if err != nil {
		log.Fatal("dialing:", err)
	}

	var report_stats_reply datastruct.ReportStatsReply
	report_stats_req := stats

	status_reported := false

	fmt.Println(stats)

	for !status_reported {
		err = collector_interface.Call("Collector.ReportStatsClient", report_stats_req, &report_stats_reply)
		if err != nil {
			log.Fatal("arith error:", err)
		}
		if report_stats_reply.Status {
			status_reported = true
		}
	}
}

func AcceptReq() error {

	// Listen on a TCP port
	l, err := net.Listen("tcp", ":80")
	if err != nil {
		log.Fatal("listen error:", err)
	}
	defer l.Close() // Ensure the listener is closed after handling the request

	// Accept exactly one connection
	conn, err := l.Accept()
	if err != nil {
		log.Fatal("accept error:", err)
	}
	defer conn.Close() // Ensure the connection is closed after serving

	// Serve RPC on the accepted connection
	rpc.ServeConn(conn)

	return nil
}
