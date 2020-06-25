package types

import "fmt"

// A CPU is a Mach-O cpu type.
type CPU uint32

const (
	cpuArchMask = 0xff000000 //  mask for architecture bits
	cpuArch64   = 0x01000000 // 64 bit ABI
	cpuArch6432 = 0x02000000 // ABI for 64-bit hardware with 32-bit types; LP32
)

const (
	CPU386     CPU = 7
	CPUAmd64   CPU = CPU386 | cpuArch64
	CPUArm     CPU = 12
	CPUArm64   CPU = CPUArm | cpuArch64
	CPUArm6432     = CPUArm | cpuArch6432
	CPUPpc     CPU = 18
	CPUPpc64   CPU = CPUPpc | cpuArch64
)

var cpuStrings = []intName{
	{uint32(CPU386), "i386"},
	{uint32(CPUAmd64), "Amd64"},
	{uint32(CPUArm), "ARM"},
	{uint32(CPUArm64), "AARCH64"},
	{uint32(CPUPpc), "PowerPC"},
	{uint32(CPUPpc64), "PowerPC 64"},
}

func (i CPU) String() string   { return stringName(uint32(i), cpuStrings, false) }
func (i CPU) GoString() string { return stringName(uint32(i), cpuStrings, true) }

type CPUSubtype uint32

// X86 subtypes
const (
	// CPUSubtypeX86All   CPUSubtype = 3
	CPUSubtypeX8664All CPUSubtype = 3
	CPUSubtypeX86Arch1 CPUSubtype = 4
	CPUSubtypeX86_64H  CPUSubtype = 8
)

// ARM subtypes
const (
	CPUSubtypeArmAll    CPUSubtype = 0
	CPUSubtypeArmV4T    CPUSubtype = 5
	CPUSubtypeArmV6     CPUSubtype = 6
	CPUSubtypeArmV5Tej  CPUSubtype = 7
	CPUSubtypeArmXscale CPUSubtype = 8
	CPUSubtypeArmV7     CPUSubtype = 9
	CPUSubtypeArmV7F    CPUSubtype = 10
	CPUSubtypeArmV7S    CPUSubtype = 11
	CPUSubtypeArmV7K    CPUSubtype = 12
	CPUSubtypeArmV8     CPUSubtype = 13
	CPUSubtypeArmV6M    CPUSubtype = 14
	CPUSubtypeArmV7M    CPUSubtype = 15
	CPUSubtypeArmV7Em   CPUSubtype = 16
	CPUSubtypeArmV8M    CPUSubtype = 17
)

// ARM64 subtypes
const (
	CPUSubtypeArm64All CPUSubtype = 0
	CPUSubtypeArm64V8  CPUSubtype = 1
	CPUSubtypeArm64E   CPUSubtype = 2
)

// Capability bits used in the definition of cpu_subtype.
const (
	CpuSubtypeFeatureMask      CPUSubtype = 0xff000000                         /* mask for feature flags */
	CpuSubtypeMask                        = CPUSubtype(^CpuSubtypeFeatureMask) /* mask for cpu subtype */
	CpuSubtypeLib64                       = 0x80000000                         /* 64 bit libraries */
	CpuSubtypePtrauthAbi                  = 0x80000000                         /* pointer authentication with versioned ABI */
	CpuSubtypePtrauthAbiUser              = 0x40000000                         /* pointer authentication with userspace versioned ABI */
	CpuSubtypeArm64PtrAuthMask            = 0x0f000000
	/*
	 *      When selecting a slice, ANY will pick the slice with the best
	 *      grading for the selected cpu_type_t, unlike the "ALL" subtypes,
	 *      which are the slices that can run on any hardware for that cpu type.
	 */
	CpuSubtypeAny = -1
)

var cpuSubtypeX86Strings = []intName{
	// {uint32(CPUSubtypeX86All), "x86"},
	{uint32(CPUSubtypeX8664All), "x86_64"},
	{uint32(CPUSubtypeX86Arch1), "x86 Arch1"},
	{uint32(CPUSubtypeX86_64H), "x86_64 (Haswell)"},
}
var cpuSubtypeArmStrings = []intName{
	{uint32(CPUSubtypeArmAll), "ArmAll"},
	{uint32(CPUSubtypeArmV4T), "ARMv4t"},
	{uint32(CPUSubtypeArmV6), "ARMv6"},
	{uint32(CPUSubtypeArmV5Tej), "ARMv5tej"},
	{uint32(CPUSubtypeArmXscale), "ARMXScale"},
	{uint32(CPUSubtypeArmV7), "ARMv7"},
	{uint32(CPUSubtypeArmV7F), "ARMv7f"},
	{uint32(CPUSubtypeArmV7S), "ARMv7s"},
	{uint32(CPUSubtypeArmV7K), "ARMv7k"},
	{uint32(CPUSubtypeArmV8), "ARMv8"},
	{uint32(CPUSubtypeArmV6M), "ARMv6m"},
	{uint32(CPUSubtypeArmV7M), "ARMv7m"},
	{uint32(CPUSubtypeArmV7Em), "ARMv7em"},
	{uint32(CPUSubtypeArmV8M), "ARMv8m"},
}
var cpuSubtypeArm64Strings = []intName{
	{uint32(CPUSubtypeArm64All), "ARM64"},
	{uint32(CPUSubtypeArm64V8), "ARM64 (ARMv8)"},
	{uint32(CPUSubtypeArm64E), "ARM64e (ARMv8.3)"},
}

func (st CPUSubtype) String(cpu CPU) string {
	switch cpu {
	case CPU386:
	case CPUAmd64:
		return stringName(uint32(st&CpuSubtypeMask), cpuSubtypeX86Strings, false)
	case CPUArm:
		return stringName(uint32(st&CpuSubtypeMask), cpuSubtypeArmStrings, false)
	case CPUArm64:
		var feature string
		caps := st & CpuSubtypeFeatureMask
		if caps&CpuSubtypePtrauthAbiUser == 0 {
			feature = fmt.Sprintf(" caps: PAC%02d", (caps&CpuSubtypeArm64PtrAuthMask)>>24)
		} else {
			feature = fmt.Sprintf(" caps: PAK%02d", (caps&CpuSubtypeArm64PtrAuthMask)>>24)
		}
		return stringName(uint32(st&CpuSubtypeMask), cpuSubtypeArm64Strings, false) + feature
	}
	return "UNKNOWN"
}

func (st CPUSubtype) GoString(cpu CPU) string {
	switch cpu {
	case CPU386:
	case CPUAmd64:
		return stringName(uint32(st&CpuSubtypeMask), cpuSubtypeX86Strings, true)
	case CPUArm:
		return stringName(uint32(st&CpuSubtypeMask), cpuSubtypeArmStrings, true)
	case CPUArm64:
		var feature string
		caps := st & CpuSubtypeFeatureMask
		if caps&CpuSubtypePtrauthAbiUser == 0 {
			feature = fmt.Sprintf(" caps: PAC%02d", (caps&CpuSubtypeArm64PtrAuthMask)>>24)
		} else {
			feature = fmt.Sprintf(" caps: PAK%02d", (caps&CpuSubtypeArm64PtrAuthMask)>>24)
		}
		return stringName(uint32(st&CpuSubtypeMask), cpuSubtypeArm64Strings, true) + feature
	}
	return "UNKNOWN"
}
