// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v3.14.0
// source: encrypted_app_ticket.proto

package protobuf

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EncryptedAppTicket struct {
	state                         protoimpl.MessageState `protogen:"open.v1"`
	TicketVersionNo               *uint32                `protobuf:"varint,1,opt,name=ticket_version_no,json=ticketVersionNo" json:"ticket_version_no,omitempty"`
	CrcEncryptedticket            *uint32                `protobuf:"varint,2,opt,name=crc_encryptedticket,json=crcEncryptedticket" json:"crc_encryptedticket,omitempty"`
	CbEncrypteduserdata           *uint32                `protobuf:"varint,3,opt,name=cb_encrypteduserdata,json=cbEncrypteduserdata" json:"cb_encrypteduserdata,omitempty"`
	CbEncryptedAppownershipticket *uint32                `protobuf:"varint,4,opt,name=cb_encrypted_appownershipticket,json=cbEncryptedAppownershipticket" json:"cb_encrypted_appownershipticket,omitempty"`
	EncryptedTicket               []byte                 `protobuf:"bytes,5,opt,name=encrypted_ticket,json=encryptedTicket" json:"encrypted_ticket,omitempty"`
	unknownFields                 protoimpl.UnknownFields
	sizeCache                     protoimpl.SizeCache
}

func (x *EncryptedAppTicket) Reset() {
	*x = EncryptedAppTicket{}
	mi := &file_encrypted_app_ticket_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EncryptedAppTicket) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptedAppTicket) ProtoMessage() {}

func (x *EncryptedAppTicket) ProtoReflect() protoreflect.Message {
	mi := &file_encrypted_app_ticket_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptedAppTicket.ProtoReflect.Descriptor instead.
func (*EncryptedAppTicket) Descriptor() ([]byte, []int) {
	return file_encrypted_app_ticket_proto_rawDescGZIP(), []int{0}
}

func (x *EncryptedAppTicket) GetTicketVersionNo() uint32 {
	if x != nil && x.TicketVersionNo != nil {
		return *x.TicketVersionNo
	}
	return 0
}

func (x *EncryptedAppTicket) GetCrcEncryptedticket() uint32 {
	if x != nil && x.CrcEncryptedticket != nil {
		return *x.CrcEncryptedticket
	}
	return 0
}

func (x *EncryptedAppTicket) GetCbEncrypteduserdata() uint32 {
	if x != nil && x.CbEncrypteduserdata != nil {
		return *x.CbEncrypteduserdata
	}
	return 0
}

func (x *EncryptedAppTicket) GetCbEncryptedAppownershipticket() uint32 {
	if x != nil && x.CbEncryptedAppownershipticket != nil {
		return *x.CbEncryptedAppownershipticket
	}
	return 0
}

func (x *EncryptedAppTicket) GetEncryptedTicket() []byte {
	if x != nil {
		return x.EncryptedTicket
	}
	return nil
}

var File_encrypted_app_ticket_proto protoreflect.FileDescriptor

const file_encrypted_app_ticket_proto_rawDesc = "" +
	"\n" +
	"\x1aencrypted_app_ticket.proto\"\x97\x02\n" +
	"\x12EncryptedAppTicket\x12*\n" +
	"\x11ticket_version_no\x18\x01 \x01(\rR\x0fticketVersionNo\x12/\n" +
	"\x13crc_encryptedticket\x18\x02 \x01(\rR\x12crcEncryptedticket\x121\n" +
	"\x14cb_encrypteduserdata\x18\x03 \x01(\rR\x13cbEncrypteduserdata\x12F\n" +
	"\x1fcb_encrypted_appownershipticket\x18\x04 \x01(\rR\x1dcbEncryptedAppownershipticket\x12)\n" +
	"\x10encrypted_ticket\x18\x05 \x01(\fR\x0fencryptedTicketB\x05H\x01\x80\x01\x00"

var (
	file_encrypted_app_ticket_proto_rawDescOnce sync.Once
	file_encrypted_app_ticket_proto_rawDescData []byte
)

func file_encrypted_app_ticket_proto_rawDescGZIP() []byte {
	file_encrypted_app_ticket_proto_rawDescOnce.Do(func() {
		file_encrypted_app_ticket_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_encrypted_app_ticket_proto_rawDesc), len(file_encrypted_app_ticket_proto_rawDesc)))
	})
	return file_encrypted_app_ticket_proto_rawDescData
}

var file_encrypted_app_ticket_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_encrypted_app_ticket_proto_goTypes = []any{
	(*EncryptedAppTicket)(nil), // 0: EncryptedAppTicket
}
var file_encrypted_app_ticket_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_encrypted_app_ticket_proto_init() }
func file_encrypted_app_ticket_proto_init() {
	if File_encrypted_app_ticket_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_encrypted_app_ticket_proto_rawDesc), len(file_encrypted_app_ticket_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_encrypted_app_ticket_proto_goTypes,
		DependencyIndexes: file_encrypted_app_ticket_proto_depIdxs,
		MessageInfos:      file_encrypted_app_ticket_proto_msgTypes,
	}.Build()
	File_encrypted_app_ticket_proto = out.File
	file_encrypted_app_ticket_proto_goTypes = nil
	file_encrypted_app_ticket_proto_depIdxs = nil
}
