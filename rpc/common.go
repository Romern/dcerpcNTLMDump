package rpc

import (
	"net"
)

type RpcInterface interface {
	GetUuid() UUID
	InvokeOp(opnum uint16, ctx *RpcContext) error
}

type RpcContext struct {
	CmnHdr            RpcCommonHdr
	CurrentBinding    RpcInterface
	Conn              net.Conn
	SupportedBindings []RpcInterface
}
