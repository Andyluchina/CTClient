package main

import (
	"CTLogchecker/ClientApp/datastruct"
	"CTLogchecker/ClientApp/services"
	"crypto/ecdh"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"strconv"

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
	curve := ecdh.P256()
	network_interface, err := rpc.DialHTTP("tcp", server_address)
	if err != nil {
		log.Fatal("dialing:", err)
	}

	client := services.NewClient(curve)
	fmt.Println(client.ReportingValue)
	client.Shamir_curve = curves.P256()
	// Synchronous call
	req := datastruct.RegistrationRequest{
		H_shuffle: client.H_shuffle,
		G_shuffle: client.G_shuffle,
		DH_Pub_H:  client.DH_Pub_H,
	}
	var reply datastruct.RegistrationResponse
	// var reply int
	err = network_interface.Call("CTLogCheckerAuditor.RegisterClient", req, &reply)
	if err != nil {
		log.Fatal("arith error:", err)
	}
	// fmt.Println(reply.AssignedID)
	client.ID = reply.AssignedID
	client.RevealThreshold = reply.RevealThreshold
	client.TotalClients = reply.TotalClients

	i_entry, err := services.CreateInitialEntry(client)
	if err != nil {
		log.Fatal("arith error:", err)
	}
	init_report_req := datastruct.InitalReportingRequest{
		ShufflerID:   client.ID,
		InitialEntry: *i_entry,
	}
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
	// ReportInitialEntrySecreteShare
	if len(Shuffle_PubKeys) != int(client.TotalClients) {
		log.Fatal("arith error: not enough keys")
	}

	// generate secrete shares
	pieces, err := services.SecreteShare(client, Shuffle_PubKeys)
	if err != nil {
		log.Fatal("arith error:", err)
	}
	// report the secrete shares
	init_report_secrete_req := datastruct.InitalReportingSecreteSharingRequest{
		ShufflerID:    client.ID,
		SecretePieces: pieces,
	}
	var init_report_secrete_reply datastruct.InitalReportingSecreteSharingReply

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

	/// perform the shuffle
	/// acquire the lock and download the database
	accquire_lock := false

	shuffle_accquire_lock_req := datastruct.ShufflePhaseAccquireLockRequest{
		ShufflerID: client.ID,
	}

	var shuffle_accquire_lock_reply datastruct.ShufflePhaseAccquireLockReply
	for !accquire_lock {
		err = network_interface.Call("CTLogCheckerAuditor.ShufflePhaseAccquireLock", shuffle_accquire_lock_req, &shuffle_accquire_lock_reply)
		if err != nil {
			log.Fatal("shuffle call error", err)
		}
		if shuffle_accquire_lock_reply.Status {
			accquire_lock = true
			fmt.Println("lock acquired ", client.ID)
		}
	}

	/// perform the shuffle
	var shuffle_res_reply datastruct.ShufflePhasePerformShuffleResultReply
	// fmt.Println(shuffle_accquire_lock_reply.Database)
	shuffle_res_req, err := services.ClientShuffle(client, shuffle_accquire_lock_reply.Database)
	if err != nil {
		log.Fatal("shuffle error:", err)
	}
	fmt.Println("Shuffling client", shuffle_res_req.ShufflerID)
	/// upload the updated database and zk proofs
	err = network_interface.Call("CTLogCheckerAuditor.ShufflePhasePerformShuffleResult", shuffle_res_req, &shuffle_res_reply)

	/// getting a ack from the auditor
	if err != nil {
		log.Fatal("network error:", err)
	}

	if !shuffle_res_reply.Status {
		panic("shuffle tempered with")
	}

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

		// perform reveal
		reveal_res_req, err := services.ClientReveal(client, reveal_reply.Database)

		if err != nil {
			log.Fatal("reveal error:", err)
		}

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

		if ft_reply.FTNeeded {
			// submit ft entries
			ft_submit_req := datastruct.FaultTolerancePhaseReportResultRequest{
				ShufflerID:      client.ID,
				DecryptedPieces: []datastruct.SecreteShareDecrypt{},
			}

			for i := 0; i < len(ft_reply.AbsentClients); i++ {
				ft_piece, err := services.ClientReportDecryptedSecret(client, ft_reply.AbsentClients[i], ft_reply.Database)
				if err != nil {
					panic(err)
				}
				ft_submit_req.DecryptedPieces = append(ft_submit_req.DecryptedPieces, *ft_piece)
			}

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
		}

	}

	if participate_in_reveal_boolean {
		fmt.Print("Client ", client.ID, " protocol completed with reveal\n")
	} else {
		fmt.Print("Client ", client.ID, " protocol completed without reveal\n")
	}

}
