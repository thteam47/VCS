// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package serverpb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ServerServiceClient is the client API for ServerService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ServerServiceClient interface {
	Login(ctx context.Context, in *LoginServer, opts ...grpc.CallOption) (*ResultLogin, error)
	Index(ctx context.Context, in *PaginationRequest, opts ...grpc.CallOption) (*ListServer, error)
	AddServer(ctx context.Context, in *Server, opts ...grpc.CallOption) (*ResponseServer, error)
	UpdateServer(ctx context.Context, in *UpdateRequest, opts ...grpc.CallOption) (*ResponseServer, error)
	DetailsServer(ctx context.Context, in *DetailsServer, opts ...grpc.CallOption) (*DetailsServerResponse, error)
	DeleteServer(ctx context.Context, in *DelServer, opts ...grpc.CallOption) (*DeleteServerResponse, error)
	ChangePassword(ctx context.Context, in *ChangePasswordRequest, opts ...grpc.CallOption) (*MessResponse, error)
	CheckStatus(ctx context.Context, in *CheckStatusRequest, opts ...grpc.CallOption) (*CheckStatusResponse, error)
	Export(ctx context.Context, in *ExportRequest, opts ...grpc.CallOption) (*ExportResponse, error)
	Logout(ctx context.Context, in *Logout, opts ...grpc.CallOption) (*MessResponse, error)
}

type serverServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewServerServiceClient(cc grpc.ClientConnInterface) ServerServiceClient {
	return &serverServiceClient{cc}
}

func (c *serverServiceClient) Login(ctx context.Context, in *LoginServer, opts ...grpc.CallOption) (*ResultLogin, error) {
	out := new(ResultLogin)
	err := c.cc.Invoke(ctx, "/server.v1.ServerService/login", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverServiceClient) Index(ctx context.Context, in *PaginationRequest, opts ...grpc.CallOption) (*ListServer, error) {
	out := new(ListServer)
	err := c.cc.Invoke(ctx, "/server.v1.ServerService/index", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverServiceClient) AddServer(ctx context.Context, in *Server, opts ...grpc.CallOption) (*ResponseServer, error) {
	out := new(ResponseServer)
	err := c.cc.Invoke(ctx, "/server.v1.ServerService/addServer", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverServiceClient) UpdateServer(ctx context.Context, in *UpdateRequest, opts ...grpc.CallOption) (*ResponseServer, error) {
	out := new(ResponseServer)
	err := c.cc.Invoke(ctx, "/server.v1.ServerService/updateServer", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverServiceClient) DetailsServer(ctx context.Context, in *DetailsServer, opts ...grpc.CallOption) (*DetailsServerResponse, error) {
	out := new(DetailsServerResponse)
	err := c.cc.Invoke(ctx, "/server.v1.ServerService/detailsServer", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverServiceClient) DeleteServer(ctx context.Context, in *DelServer, opts ...grpc.CallOption) (*DeleteServerResponse, error) {
	out := new(DeleteServerResponse)
	err := c.cc.Invoke(ctx, "/server.v1.ServerService/deleteServer", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverServiceClient) ChangePassword(ctx context.Context, in *ChangePasswordRequest, opts ...grpc.CallOption) (*MessResponse, error) {
	out := new(MessResponse)
	err := c.cc.Invoke(ctx, "/server.v1.ServerService/changePassword", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverServiceClient) CheckStatus(ctx context.Context, in *CheckStatusRequest, opts ...grpc.CallOption) (*CheckStatusResponse, error) {
	out := new(CheckStatusResponse)
	err := c.cc.Invoke(ctx, "/server.v1.ServerService/checkStatus", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverServiceClient) Export(ctx context.Context, in *ExportRequest, opts ...grpc.CallOption) (*ExportResponse, error) {
	out := new(ExportResponse)
	err := c.cc.Invoke(ctx, "/server.v1.ServerService/export", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverServiceClient) Logout(ctx context.Context, in *Logout, opts ...grpc.CallOption) (*MessResponse, error) {
	out := new(MessResponse)
	err := c.cc.Invoke(ctx, "/server.v1.ServerService/logout", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ServerServiceServer is the server API for ServerService service.
// All implementations must embed UnimplementedServerServiceServer
// for forward compatibility
type ServerServiceServer interface {
	Login(context.Context, *LoginServer) (*ResultLogin, error)
	Index(context.Context, *PaginationRequest) (*ListServer, error)
	AddServer(context.Context, *Server) (*ResponseServer, error)
	UpdateServer(context.Context, *UpdateRequest) (*ResponseServer, error)
	DetailsServer(context.Context, *DetailsServer) (*DetailsServerResponse, error)
	DeleteServer(context.Context, *DelServer) (*DeleteServerResponse, error)
	ChangePassword(context.Context, *ChangePasswordRequest) (*MessResponse, error)
	CheckStatus(context.Context, *CheckStatusRequest) (*CheckStatusResponse, error)
	Export(context.Context, *ExportRequest) (*ExportResponse, error)
	Logout(context.Context, *Logout) (*MessResponse, error)
	mustEmbedUnimplementedServerServiceServer()
}

// UnimplementedServerServiceServer must be embedded to have forward compatible implementations.
type UnimplementedServerServiceServer struct {
}

func (UnimplementedServerServiceServer) Login(context.Context, *LoginServer) (*ResultLogin, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedServerServiceServer) Index(context.Context, *PaginationRequest) (*ListServer, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Index not implemented")
}
func (UnimplementedServerServiceServer) AddServer(context.Context, *Server) (*ResponseServer, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddServer not implemented")
}
func (UnimplementedServerServiceServer) UpdateServer(context.Context, *UpdateRequest) (*ResponseServer, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateServer not implemented")
}
func (UnimplementedServerServiceServer) DetailsServer(context.Context, *DetailsServer) (*DetailsServerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DetailsServer not implemented")
}
func (UnimplementedServerServiceServer) DeleteServer(context.Context, *DelServer) (*DeleteServerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteServer not implemented")
}
func (UnimplementedServerServiceServer) ChangePassword(context.Context, *ChangePasswordRequest) (*MessResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangePassword not implemented")
}
func (UnimplementedServerServiceServer) CheckStatus(context.Context, *CheckStatusRequest) (*CheckStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckStatus not implemented")
}
func (UnimplementedServerServiceServer) Export(context.Context, *ExportRequest) (*ExportResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Export not implemented")
}
func (UnimplementedServerServiceServer) Logout(context.Context, *Logout) (*MessResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Logout not implemented")
}
func (UnimplementedServerServiceServer) mustEmbedUnimplementedServerServiceServer() {}

// UnsafeServerServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ServerServiceServer will
// result in compilation errors.
type UnsafeServerServiceServer interface {
	mustEmbedUnimplementedServerServiceServer()
}

func RegisterServerServiceServer(s grpc.ServiceRegistrar, srv ServerServiceServer) {
	s.RegisterService(&ServerService_ServiceDesc, srv)
}

func _ServerService_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginServer)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerServiceServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/server.v1.ServerService/login",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerServiceServer).Login(ctx, req.(*LoginServer))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerService_Index_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PaginationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerServiceServer).Index(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/server.v1.ServerService/index",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerServiceServer).Index(ctx, req.(*PaginationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerService_AddServer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Server)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerServiceServer).AddServer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/server.v1.ServerService/addServer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerServiceServer).AddServer(ctx, req.(*Server))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerService_UpdateServer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerServiceServer).UpdateServer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/server.v1.ServerService/updateServer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerServiceServer).UpdateServer(ctx, req.(*UpdateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerService_DetailsServer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DetailsServer)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerServiceServer).DetailsServer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/server.v1.ServerService/detailsServer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerServiceServer).DetailsServer(ctx, req.(*DetailsServer))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerService_DeleteServer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DelServer)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerServiceServer).DeleteServer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/server.v1.ServerService/deleteServer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerServiceServer).DeleteServer(ctx, req.(*DelServer))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerService_ChangePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChangePasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerServiceServer).ChangePassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/server.v1.ServerService/changePassword",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerServiceServer).ChangePassword(ctx, req.(*ChangePasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerService_CheckStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerServiceServer).CheckStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/server.v1.ServerService/checkStatus",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerServiceServer).CheckStatus(ctx, req.(*CheckStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerService_Export_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExportRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerServiceServer).Export(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/server.v1.ServerService/export",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerServiceServer).Export(ctx, req.(*ExportRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerService_Logout_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Logout)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerServiceServer).Logout(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/server.v1.ServerService/logout",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerServiceServer).Logout(ctx, req.(*Logout))
	}
	return interceptor(ctx, in, info, handler)
}

// ServerService_ServiceDesc is the grpc.ServiceDesc for ServerService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ServerService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "server.v1.ServerService",
	HandlerType: (*ServerServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "login",
			Handler:    _ServerService_Login_Handler,
		},
		{
			MethodName: "index",
			Handler:    _ServerService_Index_Handler,
		},
		{
			MethodName: "addServer",
			Handler:    _ServerService_AddServer_Handler,
		},
		{
			MethodName: "updateServer",
			Handler:    _ServerService_UpdateServer_Handler,
		},
		{
			MethodName: "detailsServer",
			Handler:    _ServerService_DetailsServer_Handler,
		},
		{
			MethodName: "deleteServer",
			Handler:    _ServerService_DeleteServer_Handler,
		},
		{
			MethodName: "changePassword",
			Handler:    _ServerService_ChangePassword_Handler,
		},
		{
			MethodName: "checkStatus",
			Handler:    _ServerService_CheckStatus_Handler,
		},
		{
			MethodName: "export",
			Handler:    _ServerService_Export_Handler,
		},
		{
			MethodName: "logout",
			Handler:    _ServerService_Logout_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "server.proto",
}
