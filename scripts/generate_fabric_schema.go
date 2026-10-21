// Run from a service-discovery-platform checkout at
// 809d3cda592261f0a5f2d323ede2c1ae10fd2bf3:
// go run /path/to/lemur/scripts/generate_fabric_schema.go /path/to/lemur/lemur/sources/fabric.pb
// Export the upstream descriptors unchanged, including their dependencies.
package main

import (
	"os"

	fabric "github.com/DataDog/service-discovery-platform/pkg/pb/fabric/api/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func main() {
	set := &descriptorpb.FileDescriptorSet{}
	seen := map[string]bool{}
	var add func(protoreflect.FileDescriptor)
	add = func(file protoreflect.FileDescriptor) {
		if seen[file.Path()] {
			return
		}
		seen[file.Path()] = true
		for i := 0; i < file.Imports().Len(); i++ {
			add(file.Imports().Get(i).FileDescriptor)
		}
		set.File = append(set.File, protodesc.ToFileDescriptorProto(file))
	}
	add((&fabric.ListRequest{}).ProtoReflect().Descriptor().ParentFile())
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(set)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], data, 0644); err != nil {
		panic(err)
	}
}
