package pfstats

/*
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
unmask(struct pf_addr_wrap *a)
{
	int i = 31, j = 0, b = 0;
	u_int32_t tmp;
	struct pf_addr *m;

	m = &a->v.a.mask;

	while (j < 4 && m->addr32[j] == 0xffffffff) {
		b += 32;
		j++;
	}

	if (j < 4) {
		tmp = ntohl(m->addr32[j]);
		for (i = 31; tmp & (1 << i); --i)
			b++;
	}

	return b;
}

char*
pfaddr(struct pf_addr_wrap *a, int af){
	int bits;
	char addr[INET6_ADDRSTRLEN];
	char *s = malloc(INET6_ADDRSTRLEN*2+2);
	memset(s, 0, INET6_ADDRSTRLEN*2+2);
	switch(a->type){
	case PF_ADDR_ADDRMASK:
		addr[0] = 0;
		inet_ntop(af, &a->v.a.addr, addr, INET6_ADDRSTRLEN);
		if(addr[0] == 0){
			switch(af){
			default:
				strlcpy(addr, "0", 2);
			case AF_INET:
				strlcpy(addr, "0.0.0.0", 8);
				break;
			case AF_INET6:
				strlcpy(addr, "::", 3);
				break;
			}
		}
		bits = unmask(a);
		snprintf(s, INET6_ADDRSTRLEN*2+2, "%s/%d", addr, bits);
		break;
	case PF_ADDR_DYNIFTL:
		snprintf(s, INET6_ADDRSTRLEN, "(%s)", a->v.ifname);
		break;
	}

	return s;
}

void
pfsetaddr(struct pf_addr_wrap *a, int af, char *addr, char *mask)
{
	memset(&a->v.a, 0, sizeof(a->v.a));

	switch(af){
	case AF_INET:
		if(inet_pton(af, addr, &a->v.a.addr.v4.s_addr) != 1)
			return;
		if(inet_pton(af, mask, &a->v.a.mask.v4.s_addr) != 1)
			return;
		break;
	case AF_INET6:
		if(inet_pton(af, addr, &a->v.a.addr.v6.s6_addr) != 1)
			return;
		if(inet_pton(af, mask, &a->v.a.mask.v6.s6_addr) != 1)
			return;
		break;
	}
}

char*
pfgetifname(struct pf_addr_wrap *a)
{
	return a->v.ifname;
}

void
pfsetifname(struct pf_addr_wrap *a, char *ifname){
	memset(&a->v.a.addr, 0x0, sizeof(a->v.a.addr));
	memset(&a->v.a.mask, 0xff, sizeof(a->v.a.mask));
	strlcpy(a->v.ifname, ifname, sizeof(a->v.ifname));
}

uint16_t
cntohs(uint16_t v){
	return ntohs(v);
}

uint16_t
chtons(uint16_t v){
	return htons(v);
}

*/
import "C"
import (
	"os"
	"syscall"
	"unsafe"
)

const (
	DIOCGETSTATUS = C.DIOCGETSTATUS
)

func ioctl(fd, op, arg uintptr) error {
	_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
	if ep != 0 {
		return syscall.Errno(ep)
	}
	return nil
}

type OpenPf struct {
	fd *os.File
}

func Open() (Pf, error) {
	pf := new(OpenPf)

	fd, err := os.OpenFile("/dev/pf", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	pf.fd = fd

	return pf, nil
}

func (p *OpenPf) Close() error {
	return p.fd.Close()
}

type OpenStats struct {
	s C.struct_pf_status
}

func (s *OpenStats) Enabled() bool {
	return s.s.running != 0
}

func (s *OpenStats) StateCount() int {
	return int(s.s.states)
}

func (s *OpenStats) StateSearches() int {
	return int(s.s.fcounters[0])
}

func (s *OpenStats) StateInserts() int {
	return int(s.s.fcounters[1])
}

func (s *OpenStats) StateRemovals() int {
	return int(s.s.fcounters[2])
}

func (p *OpenPf) Stats() (Stats, error) {
	stats := C.struct_pf_status{}

	err := ioctl(p.fd.Fd(), DIOCGETSTATUS, uintptr(unsafe.Pointer(&stats)))
	if err != nil {
		return nil, err
	}

	return &OpenStats{s: stats}, nil
}
