package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/ark-sandbox/OpenWMI/rpc"

	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
	"github.com/lunixbochs/struc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/dcetypes"
)

func MapResponse(ctx *rpc.RpcContext, reqHdr *rpc.RpcRequestHeader) {
	//fmt.Println("MapResponse called")
	cmnHdr := ctx.CmnHdr
	cmnHdr.PType = rpc.PktResponse
	respHdr := rpc.RpcResponseHeader{}
	respHdr.AllocHint = 4
	respHdr.PresCtxId = 0
	respHdr.AlertCount = 0
	respHdr.Padding = 0
	spooluuid, _ := uuid.Parse("12345678-1234-abcd-ef00-0123456789ab")
	ndruuid, _ := uuid.Parse("8a885d04-1ceb-11c9-9fe8-08002b104860")

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(44444))

	respHdr.StubData = append([]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4b, 0x0, 0x0, 0x0},
		dcetypes.FloorsToTower([]*dcetypes.Floor{
			{
				Protocol:     uint8(dcetypes.ProtocolUUID),
				VersionMajor: 1,
				UUID:         spooluuid,
				Data:         []byte{0, 0},
			},
			{
				Protocol:     uint8(dcetypes.ProtocolUUID),
				VersionMajor: 2,
				UUID:         ndruuid,
				Data:         []byte{0, 0},
			},
			{
				Protocol: uint8(dcetypes.ProtocolRPC_CO),
				Data:     []byte{0, 0},
			},
			{
				Protocol: uint8(dcetypes.ProtocolTCP),
				Data:     port,
			},
			{
				Protocol: uint8(dcetypes.ProtocolIP),
				Data:     []byte{192, 168, 64, 1},
			},
		}).TowerOctetString...)
	respHdr.StubData = append(respHdr.StubData, 0x0, 0x0, 0x0, 0x0, 0x0)
	//Calculate Frame length
	cmnHdrLen, _ := struc.Sizeof(&cmnHdr)
	respHdrLen, err := struc.Sizeof(&respHdr)
	cmnHdr.FragLen = uint16(cmnHdrLen + respHdrLen)
	//fmt.Printf("Setting fragment length to %v", cmnHdr.FragLen)
	//spew.Dump(cmnHdr)
	buff := new(bytes.Buffer)
	struc.Pack(buff, &cmnHdr)
	//fmt.Printf("Packed commonHeader\n")
	//spew.Dump(respHdr)
	err = struc.Pack(buff, &respHdr)
	if err != nil {
		fmt.Println(err)
	}

	//fmt.Printf("Packed responseHdr\n")
	//fmt.Println("Debug: bindAckHdr size:", len(buff.Bytes()))
	ctx.Conn.Write(buff.Bytes())
}

func handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	fmt.Println("Client connected from " + remoteAddr)
	ctx := new(rpc.RpcContext)
	ctx.CurrentBinding = nil
	ctx.Conn = conn
	for {
		cmnHdr := rpc.RpcCommonHdr{}
		struc.Unpack(conn, &cmnHdr)
		ctx.CmnHdr = cmnHdr
		if !(cmnHdr.MajVer == 5 && cmnHdr.MinVer == 0) {
			fmt.Printf("RPC version mismatched %v, %v\n", cmnHdr.MajVer, cmnHdr.MinVer)
			conn.Close()
			break
		}

		//fmt.Println("*_******************* NEW PDU ********************_*")
		//spew.Dump(cmnHdr)
		switch cmnHdr.PType {
		case rpc.PktRequest:
			handleRpcRequest(ctx)
		case rpc.PktBind:
			handleRpcBindRequest(ctx)
		case rpc.PktAuth3:
			handleRpcPktAuth(ctx)
		default:
			fmt.Println("Unsupported Packet Type:", cmnHdr.PType)
			conn.Close()
		}
	}
}

func handleRpcPktAuth(ctx *rpc.RpcContext) {
	//fmt.Println("AUTH3 packet received\n")
	hdr := make([]byte, 4)
	io.ReadFull(ctx.Conn, hdr)
	authHdr := rpc.RpcComAuthTrailer{}
	struc.Unpack(ctx.Conn, &authHdr)

	buff := make([]byte, ctx.CmnHdr.AuthLen+uint16(authHdr.PaddingLen))
	io.ReadFull(ctx.Conn, buff)
	//spew.Dump(buff)

	resp, err := ntlm.ParseAuthenticateMessage(buff, 2)
	if err != nil {
		fmt.Println("CreateServerSession returned error:", err)
	}
	fmt.Println("NTLM Response:", resp)

}
func handleAuthHeader(ctx *rpc.RpcContext) (rpc.RpcComAuthTrailer, []byte) {
	if ctx.CmnHdr.AuthLen != 0 {
		authHdr := rpc.RpcComAuthTrailer{}
		buff := make([]byte, ctx.CmnHdr.AuthLen)
		struc.Unpack(ctx.Conn, &authHdr)
		if authHdr.AuthType != 10 {
			fmt.Println("Receveid Non-NTLMSSP message: Only NTLMSSP is supported")
		}

		io.ReadFull(ctx.Conn, buff)

		session, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionlessMode)
		if err != nil {
			fmt.Println("CreateServerSession returned error:", err)
		}
		challenge, err := session.GenerateChallengeMessage()
		return authHdr, challenge.Bytes()
	}
	return rpc.RpcComAuthTrailer{}, nil
}

func handleRpcRequest(ctx *rpc.RpcContext) {
	//fmt.Println("handleRpcRequest\n")
	reqHdr := rpc.RpcRequestHeader{}
	struc.Unpack(ctx.Conn, &reqHdr)
	//spew.Dump(reqHdr)
	//fmt.Printf("Opnum Received: %v\n", &reqHdr.OpNum)
	switch reqHdr.OpNum {
	case 3: //MapRequest
		MapResponse(ctx, &reqHdr)
	default:

	}
}

func handleRpcBindRequest(ctx *rpc.RpcContext) {
	bindHdr := rpc.RpcBindHdr{}
	struc.Unpack(ctx.Conn, &bindHdr)

	var authHdr rpc.RpcComAuthTrailer
	var authResponse []byte

	//Successfully bound, but for check for auth headers.
	if ctx.CmnHdr.AuthLen > 0 {
		authHdr, authResponse = handleAuthHeader(ctx)
	}

	sendBindAck(ctx, bindHdr, authHdr, authResponse)
}

func sendBindAck(ctx *rpc.RpcContext, bindHdr rpc.RpcBindHdr, authHdr rpc.RpcComAuthTrailer, authResponse []byte) {
	cmnHdr := ctx.CmnHdr
	cmnHdr.PType = rpc.PktBindAck
	cmnHdr.AuthLen = 0
	cmnHdr.FragLen = 0
	//Construct BindAckHdr
	bindAckHdr := rpc.RpcBindAckHdr{}
	bindAckHdr.MaxXmitFrag = bindHdr.MaxXmitFrag
	bindAckHdr.MaxRecvFrag = bindHdr.MaxRecvFrag
	bindAckHdr.AssocGrpId = 0x1234
	bindAckHdr.PortAddress.Address = []byte("135")
	bindAckHdr.PortAddress.Length = uint16(len(bindAckHdr.PortAddress.Address))
	rpc_syntax_negotiation_result := make([]rpc.RPCSyntaxNegotiationResult, len(bindHdr.SyntaxNegList.SyntaxList))
	rpc_syntax_negotiation_result[0].Reason = 2
	rpc_syntax_negotiation_result[0].Result = 2
	rpc_syntax_negotiation_result[1].Reason = 0
	rpc_syntax_negotiation_result[1].Result = 0
	rpc_syntax_negotiation_result[1].AcceptedUuid = bindHdr.SyntaxNegList.SyntaxList[1].TransferSyntax[0]
	rpc_syntax_negotiation_result[2].Reason = 3
	rpc_syntax_negotiation_result[2].Result = 3

	bindAckHdr.SyntaxNegResultList = rpc.RPCSyntaxNegotiationResultList{3, 0, 0, rpc_syntax_negotiation_result}

	cmnHdrLen, _ := struc.Sizeof(cmnHdr)
	bindAckHdrLen, _ := struc.Sizeof(&bindAckHdr)
	//spew.Dump(cmnHdr)
	buff := new(bytes.Buffer)
	cmnHdr.FragLen = uint16(cmnHdrLen + bindAckHdrLen)
	if authResponse != nil {
		cmnHdr.AuthLen = uint16(len(authResponse))
		cmnHdr.FragLen = uint16(cmnHdrLen+bindAckHdrLen) + cmnHdr.AuthLen + rpc.RpcComAuthTrailerLen
	}
	struc.Pack(buff, &cmnHdr)
	struc.Pack(buff, &bindAckHdr)
	if authResponse != nil {
		struc.Pack(buff, &authHdr)
		buff.Write(authResponse)
	}
	ctx.Conn.Write(buff.Bytes())
}

func main() {
	listenerEPM, err := net.Listen("tcp", "0.0.0.0:135")
	if err != nil {
		fmt.Println("Error on binding ", err)
		return
	}
	listenerSpoolSS, err := net.Listen("tcp", "0.0.0.0:44444")
	if err != nil {
		fmt.Println("Error on binding ", err)
		return
	}

	for {
		connEPM, err := listenerEPM.Accept()
		if err != nil {
			fmt.Println("Some error occurred in connection accept")
		}
		go handleConnection(connEPM)
		fmt.Println("handling epm")
		connSpoolSS, err := listenerSpoolSS.Accept()
		if err != nil {
			fmt.Println("Some error occurred in connection accept")
		}
		go handleConnection(connSpoolSS)
		fmt.Println("handling spoolss")
	}
	wait := make(chan int)
	<-wait
}
